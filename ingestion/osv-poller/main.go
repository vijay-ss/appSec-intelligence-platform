// OSV Poller — publishes normalised VulnerabilityEvents to Kafka topic: vulns.osv.raw
//
// Two-phase design:
//
//  Phase 1 — GCS Bulk Load (first run only)
//    Downloads the full OSV dataset for each ecosystem from Google Cloud Storage.
//    Each ecosystem is a single zip file containing one JSON record per vulnerability.
//    Tracks the highest `modified` timestamp seen across all records and writes it
//    to Redis as the incremental cursor, then sets osv:bulk_loaded = "1".
//
//  Phase 2 — REST API Incremental Poll (runs forever)
//    Reads the cursor from Redis, calls the OSV REST API with modified_since=cursor,
//    paginates through results, publishes new/updated records, and advances the cursor.
//    Runs every OSV_POLL_INTERVAL_SECONDS (default 600).
//
// The cursor is the only handoff between the two phases. Phase 2 does not know
// or care whether the cursor was written by Phase 1 or by a previous Phase 2 iteration.
// The Flink deduplicator handles any overlap at the boundary.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	sharedkafka "github.com/vijay-ss/appsec-intelligence/ingestion/shared/kafka"
	"github.com/vijay-ss/appsec-intelligence/ingestion/shared/metrics"
	"github.com/vijay-ss/appsec-intelligence/ingestion/shared/schemas"
)

const (
	osvTopic         = "vulns.osv.raw"
	osvBulkLoadedKey = "osv:bulk_loaded"
	osvCursorKey     = "osv:cursor:last_modified"
	osvGCSBase       = "https://osv-vulnerabilities.storage.googleapis.com"
	osvAPIBase       = "https://api.osv.dev/v1"
	osvFetchDelay 	 = 50 * time.Millisecond
)

var targetEcosystems = []string{"PyPI", "npm", "Maven", "Go", "crates.io", "RubyGems"}

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	metrics.Init(getenv("METRICS_PORT", "2112"))

	brokers := getenv("KAFKA_BROKERS", "localhost:9092")
	redisAddr := getenv("REDIS_ADDR", "localhost:6379")
	pollSecs := getenvInt("OSV_POLL_INTERVAL_SECONDS", 300)

	producer, err := sharedkafka.NewProducer(brokers)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create kafka producer")
	}
	defer producer.Close()

	rdb := redis.NewClient(&redis.Options{Addr: redisAddr})
	ctx := context.Background()

	log.Info().
		Str("brokers", brokers).
		Int("poll_interval_seconds", pollSecs).
		Msg("osv poller starting")
	
	if err := bulkLoadIfNeeded(ctx, rdb, producer); err != nil {
		log.Error().
			Err(err).
			Msg("bulk load failed — falling through to incremental polling")
	}
	
	pollIncremental(ctx, rdb, producer)
	ticker := time.NewTicker(time.Duration(pollSecs) * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		pollIncremental(ctx, rdb, producer)
	}

}

// pollIncremental reads the cursor from Redis, discovers all vulnerabilities
// modified since that timestamp via modified_id.csv, fetches each full record
// from the OSV REST API, publishes to Kafka, and advances the cursor to now.
func pollIncremental(ctx context.Context, rdb *redis.Client, producer *sharedkafka.Producer) {
	cursor, err := rdb.Get(ctx, osvCursorKey).Result()
	if err == redis.Nil {
		cursor = time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339)
		log.Warn().
			Str("cursor", cursor).
			Msg("no osv cursor found — falling back to 24h lookback")
	} else if err != nil {
		log.Error().
			Err(err).
			Msg("failed to read osv cursor from redis")
		return
	}
	
	log.Info().Str("modified_since", cursor).Msg("osv incremental poll starting")
	
	published, err := fetchAndPublishSince(ctx, cursor, producer)
	if err != nil {
		log.Error().Err(err).Msg("osv incremental poll failed")
		return
	}

	newCursor := time.Now().UTC().Format(time.RFC3339)
	if err := rdb.Set(ctx, osvCursorKey, newCursor, 0).Err(); err != nil {
		log.Error().Err(err).Msg("failed to advance osv cursor")
	}

	log.Info().
		Int("published", published).
		Str("new_cursor", newCursor).
		Msg("osv incremental poll complete")
}

// fetchAndPublishSince pages through the OSV API fetching all vulnerabilities
// modified since the given RFC3339 timestamp. Returns the total published count.
func fetchAndPublishSince(ctx context.Context, modifiedSince string, producer *sharedkafka.Producer) (int, error) {
	cursor, err := time.Parse(time.RFC3339, modifiedSince)
	if err != nil {
		return 0, fmt.Errorf("parse cursor: %w", err)
	}
	
	total := 0
	
	for _, ecosystem := range targetEcosystems {
		count, err := fetchEcosystemSince(ctx, ecosystem, cursor, producer)
		if err != nil {
			log.Error().
				Err(err).
				Str("ecosystem", ecosystem).
				Msg("incremental fetch failed for ecosystem")
			continue
		}
		total += count
	}
	
	return total, nil
}

// fetchEcosystemSince fetches the modified_id.csv index for one ecosystem,
// collects IDs modified after the cursor, fetches each full record by ID from
// the OSV REST API, and publishes to Kafka.
func fetchEcosystemSince(ctx context.Context, ecosystem string, cursor time.Time, producer *sharedkafka.Producer) (int, error) {
	// Step 1: stream modified_id.csv from GCS.
	// Format: one "VULN-ID,RFC3339-timestamp" pair per line, sorted newest-first.
	// Stops reading as soon as a timestamp exists at or before the cursor —
	// everything after that point was already processed in a previous poll.
	csvUrl := fmt.Sprintf("%s/%s/modified_id.csv", osvGCSBase, ecosystem)
	
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, csvUrl, nil)
	if err != nil {
		return 0, fmt.Errorf("build csv request: %w", err)
	}
	
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return 0, fmt.Errorf("fetch modified_id.csv: %w", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("gcs returned HTTP %d for %s", resp.StatusCode, csvUrl)
	}
	
	var newIDs []string
	
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		
		parts := strings.SplitN(line, ",", 2)
		if len(parts) != 2 {
			log.Warn().
				Str("line", line).
				Msg("skipping malformed modified_id.csv line")
			continue
		}
		
		modifiedStr := strings.TrimSpace(parts[0])
		id := strings.TrimSpace(parts[1])
		
		modified, err := time.Parse(time.RFC3339, modifiedStr)
		if err != nil {
			// Try without nanoseconds — OSV sometimes omits them.
			modified, err = time.Parse("2006-01-02T15:04:05Z", modifiedStr)
			if err != nil {
				log.Warn().
					Str("id", id).
					Str("modified", modifiedStr).
					Msg("skipping unparseable timestamp")
				continue
			}
		}
		
		// The CSV is sorted newest-first, so once we see a record at or before
		// the cursor we can stop — everything remaining is already processed.
		if !modified.After(cursor) {
			break
		}
		
		newIDs = append(newIDs, id)
	}
	
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("read modified_id.csv: %w", err)
	}
	
	if len(newIDs) == 0 {
		return 0, nil
	}
	
	log.Info().
		Str("ecosystem", ecosystem).
		Int("new_ids", len(newIDs)).
		Msg("fetching new vulnerability records")
	
	// Step 2: fetch each new record by ID from the OSV REST API.
	// GET /v1/vulns/{id} returns the full osvVuln record for a single ID.
	published := 0
	for _, id := range newIDs {
		vuln, err := fetchVulnByID(ctx, id)
		if err != nil {
			log.Error().
				Err(err).
				Str("id", id).
				Msg("failed to fetch vuln by id — skipping")
			continue
		}
		
		for _, event := range normalizeOSV(*vuln) {
			payload, _ := json.Marshal(event)
			if err := producer.Publish(osvTopic, event.CVEID, payload); err != nil {
				log.Error().
					Err(err).
					Str("cve_id", event.CVEID).
					Msg("failed to publish vuln event")
			} else {
				published++
			}
		}
		
		time.Sleep(osvFetchDelay)
	}
	
	return published, nil
}

// fetchVulnByID fetches a single OSV vulnerability record by its ID.
// Uses GET /v1/vulns/{id}
func fetchVulnByID(ctx context.Context, id string) (*osvVuln, error) {
	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		fmt.Sprintf("%s/vulns/%s", osvAPIBase, id),
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("get vuln: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		log.Warn().Str("id", id).Msg("osv api rate limited — sleeping 60s")
		time.Sleep(60 * time.Second)
		return fetchVulnByID(ctx, id) // single retry after backoff
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("osv api returned HTTP %d for id %s", resp.StatusCode, id)
	}
	
	var vuln osvVuln
	if err := json.NewDecoder(resp.Body).Decode(&vuln); err != nil {
		return nil, fmt.Errorf("decode vuln: %w", err)
	}
	
	return &vuln, nil
}

// osvVuln is the shared record format used by both the REST API and GCS zip files.
type osvVuln struct {
	ID        string    `json:"id"`
	Modified  time.Time `json:"modified"`
	Published time.Time `json:"published"`
	Aliases   []string  `json:"aliases"`
	Summary   string    `json:"summary"`
	Details   string    `json:"details"`
	Affected  []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced,omitempty"`
				Fixed       string `json:"fixed,omitempty"`
			} `json:"events"`
		} `json:"ranges"`
		Versions []string `json:"versions"`
	} `json:"affected"`
}

// normaliseOSV converts a raw OSV vulnerability record into one
// VulnerabilityEvent per affected package. A single OSV record can affect
// multiple packages (e.g. both PyPI and npm distributions of the same library),
// so we emit one event per affected package to keep the Flink join simple.
func normalizeOSV(v osvVuln) []*schemas.VulnerabilityEvent {
	cveID := v.ID
	for _, alias := range v.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			cveID = alias
			break
		}
	}

	description := v.Summary
	if description == "" {
		description = v.Details
	}

	var events []*schemas.VulnerabilityEvent

	for _, affected := range v.Affected {
		if affected.Package.Name == "" {
			continue
		}

		safeVersion := ""
		versionRange := ""
		for _, r := range affected.Ranges {
			if r.Type == "ECOSYSTEM" {
				for _, e := range r.Events {
					if e.Fixed != "" {
						safeVersion = e.Fixed
						versionRange = fmt.Sprintf("< %s", e.Fixed)
					}
				}
			}
		}

		events = append(events, &schemas.VulnerabilityEvent{
			EventID:              uuid.NewString(),
			CVEID:                cveID,
			Source:               "osv",
			PublishedAt:          v.Published,
			IngestedAt:           time.Now().UTC(),
			SeverityTier:         "MEDIUM",
			Description:          description,
			AffectedPackage:      affected.Package.Name,
			Ecosystem:            normaliseEco(affected.Package.Ecosystem),
			AffectedVersionRange: versionRange,
			SafeVersion:          safeVersion,
			AffectedVersions:     affected.Versions,
		})
	}

	return events
}

func normaliseEco(raw string) string {
	m := map[string]string{
		"PyPI": "pypi", "npm": "npm", "Maven": "maven",
		"Go": "go", "crates.io": "cargo", "RubyGems": "rubygems",
	}
	if v, ok := m[raw]; ok {
		return v
	}
	return strings.ToLower(raw)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		var i int
		fmt.Sscanf(v, "%d", &i)
		return i
	}
	return fallback
}