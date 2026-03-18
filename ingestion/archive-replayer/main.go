// Archive Replayer — downloads and replays GitHub Archive hourly files.
// Filters for merged Dependabot/Renovate PRs from 2024 onwards and publishes
// DependencyChangeEvents to Kafka topic: deps.changes
//
// Three operating modes:
//   seed       — replay start→end at configured speed, exit when done
//   loadtest   — replay at max speed for throughput demonstration
//   continuous — replay one day at a time, loop indefinitely
//
// Uses repo name directly as service_id, matching the GitHub Events API poller.
//
// Usage:
//   go run main.go --start-date 2024-01-01 --end-date 2025-01-01 --mode seed
//   go run main.go --start-date 2024-01-01 --end-date 2024-02-01 --mode loadtest --speed 0
package main

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"

	sharedkafka "github.com/vijay-ss/appsec-intelligence/ingestion/shared/kafka"
	"github.com/vijay-ss/appsec-intelligence/ingestion/shared/metrics"
	"github.com/vijay-ss/appsec-intelligence/ingestion/shared/schemas"
)

// Pre-2024 data has outdated package versions that don't match current CVEs
// and predates reliable Dependabot adoption.
var minArchiveDate = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

var depBumpRe = regexp.MustCompile(
	`(?i)bump (?P<pkg>[\w\-\.\/]+) from (?P<from>[\d\.]+) to (?P<to>[\d\.]+)`,
)

var (
	startDate  string
	endDate    string
	speedMs    int64
	mode       string
)

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	metrics.Init(getenv("METRICS_PORT", "2112"))
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	root := &cobra.Command{
		Use:   "archive-replayer",
		Short: "Replay GitHub Archive dep change events into Kafka",
		RunE:  run,
	}
	root.Flags().StringVar(&startDate, "start-date", "", "Start date YYYY-MM-DD (required, min 2024-01-01)")
	root.Flags().StringVar(&endDate, "end-date", "", "End date YYYY-MM-DD (required)")
	root.Flags().StringVar(&mode, "mode", "seed", "Mode: seed | loadtest | continuous")
	root.Flags().Int64Var(&speedMs, "delay-ms", 0, "Milliseconds between events (0 = max speed)")
	root.MarkFlagRequired("start-date")
	root.MarkFlagRequired("end-date")

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, _ []string) error {
	brokers := getenv("KAFKA_BROKERS", "localhost:9092")
	producer, err := sharedkafka.NewProducer(brokers)
	if err != nil {
		return fmt.Errorf("kafka producer: %w", err)
	}
	defer producer.Close()

	start, err := time.Parse("2006-01-02", startDate)
	if err != nil {
		return fmt.Errorf("invalid start-date: %w", err)
	}
	end, err := time.Parse("2006-01-02", endDate)
	if err != nil {
		return fmt.Errorf("invalid end-date: %w", err)
	}
	if start.Before(minArchiveDate) {
		log.Warn().Msg("start-date before 2024-01-01 — adjusting to minimum")
		start = minArchiveDate
	}

	log.Info().
		Str("mode", mode).
		Str("start", start.Format("2006-01-02")).
		Str("end", end.Format("2006-01-02")).
		Int64("delay_ms", speedMs).
		Msg("archive replayer starting")

	switch mode {
	case "seed", "loadtest":
		return replayRange(producer, start, end)
	case "continuous":
		return replayContinuous(producer, start)
	default:
		return fmt.Errorf("unknown mode %q — use seed | loadtest | continuous", mode)
	}
}

func replayRange(producer *sharedkafka.Producer, start, end time.Time) error {
	total := 0
	for d := start; !d.After(end); d = d.Add(24 * time.Hour) {
		dayCount := 0
		for h := 0; h < 24; h++ {
			n, err := replayHour(producer, d, h)
			if err != nil {
				log.Error().Err(err).Str("date", d.Format("2006-01-02")).Int("hour", h).Msg("skipping hour")
				continue
			}
			dayCount += n
		}
		total += dayCount
		log.Info().
			Str("date", d.Format("2006-01-02")).
			Int("day_events", dayCount).
			Int("total_events", total).
			Msg("day replayed")
	}
	log.Info().Int("total", total).Msg("replay complete — exiting (seed/loadtest mode)")
	return nil
}

func replayContinuous(producer *sharedkafka.Producer, start time.Time) error {
	current := start
	for {
		yesterday := time.Now().UTC().Truncate(24 * time.Hour).Add(-24 * time.Hour)
		if current.After(yesterday) {
			log.Info().Msg("continuous mode: caught up — sleeping 24h")
			time.Sleep(24 * time.Hour)
			continue
		}
		for h := 0; h < 24; h++ {
			replayHour(producer, current, h) //nolint:errcheck
		}
		current = current.Add(24 * time.Hour)
	}
}

func replayHour(producer *sharedkafka.Producer, date time.Time, hour int) (int, error) {
	url := fmt.Sprintf(
		"https://data.gharchive.org/%s-%d.json.gz",
		date.Format("2006-01-02"),
		hour,
	)
	
	log.Info().Str("url", url).Msgf("fetching archive for %s at hour %d:00", date.Format("2006-01-02"), hour)
	resp, err := http.Get(url)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return 0, nil // archive file not yet available — not an error
	}

	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()

	count := 0
	scanner := bufio.NewScanner(gz)
	// GH Archive lines can be large — use a 4MB buffer.
	scanner.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)

	for scanner.Scan() {
		dep := parseArchiveLine(scanner.Bytes())
		if dep == nil {
			continue
		}
		payload, _ := json.Marshal(dep)
		producer.Publish("deps.changes", dep.ServiceID, payload) //nolint:errcheck
		count++

		if speedMs > 0 {
			time.Sleep(time.Duration(speedMs) * time.Millisecond)
		}
	}
	return count, scanner.Err()
}

// parseArchiveLine applies all filtering and parsing in one pass.
// Returns nil for the vast majority of events that aren't merged dep-bump PRs.
func parseArchiveLine(line []byte) *schemas.DependencyChangeEvent {
	// Fast pre-filter: skip lines without PullRequestEvent entirely.
	if !strings.Contains(string(line), "PullRequestEvent") {
		return nil
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(line, &raw); err != nil {
		return nil
	}

	if raw["type"] != "PullRequestEvent" {
		return nil
	}

	payload, _ := raw["payload"].(map[string]interface{})
	if payload["action"] != "closed" {
		return nil
	}

	pr, _ := payload["pull_request"].(map[string]interface{})
	if merged, _ := pr["merged"].(bool); !merged {
		return nil
	}

	mergedAtStr, _ := pr["merged_at"].(string)
	mergedAt, err := time.Parse(time.RFC3339, mergedAtStr)
	if err != nil || mergedAt.Before(minArchiveDate) {
		return nil
	}

	actor, _ := raw["actor"].(map[string]interface{})
	login, _ := actor["login"].(string)
	login = strings.ToLower(login)
	if !strings.Contains(login, "dependabot") && !strings.Contains(login, "renovate") {
		return nil
	}

	head, _ := pr["head"].(map[string]interface{})
	branchRef, _ := head["ref"].(string)
	eco := schemas.EcosystemFromBranch(branchRef)
	if eco == "" {
		return nil
	}

	title, _ := pr["title"].(string)
	pkg, fromV, toV := parseBumpTitle(title)
	if pkg == "" || toV == "" {
		return nil
	}

	repoObj, _ := raw["repo"].(map[string]interface{})
	repoName, _ := repoObj["name"].(string)

	prNum := 0
	if n, ok := pr["number"].(float64); ok {
		prNum = int(n)
	}

	return &schemas.DependencyChangeEvent{
		EventID:      uuid.NewString(),
		Source:       "gh_archive",
		Repo:         repoName,
		ServiceID:    repoName, // repo name is service_id for archive events
		PRNumber:     prNum,
		Author:       login,
		Ecosystem:    eco,
		ManifestFile: schemas.ManifestForEcosystem(eco),
		Updated:      []schemas.DependencyUpdate{{Package: pkg, FromVersion: fromV, ToVersion: toV}},
		OccurredAt:   mergedAt,
		IngestedAt:   time.Now().UTC(),
	}
}

func parseBumpTitle(title string) (pkg, from, to string) {
	m := depBumpRe.FindStringSubmatch(title)
	if m == nil {
		return
	}
	for i, name := range depBumpRe.SubexpNames() {
		switch name {
		case "pkg":
			pkg = m[i]
		case "from":
			from = m[i]
		case "to":
			to = m[i]
		}
	}
	return
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
