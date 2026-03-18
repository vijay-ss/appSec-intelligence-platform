// GitHub Events API Poller — polls 15 target repos every 60 seconds.
// Filters for merged Dependabot/Renovate PRs and publishes DependencyChangeEvents
// to Kafka topic: deps.changes
//
// Uses repo name directly as service_id. The service registry is pre-seeded
// with entries for all target repos so blast radius scoring has metadata.
//
// Rate limits: 5,000 req/hour with token. 15 repos × 1 req/min = 900 req/hour.
// With ETag caching, only repos with new activity consume rate limit tokens —
// unchanged repos return HTTP 304 and cost nothing against the quota.
package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"regexp"
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
	depsTopic    = "deps.changes"
	pollInterval = 60 * time.Second
	etagKeyPrefix = "github:etag:"
)

var targetRepos = []string{
	"psf/requests",
    "pydantic/pydantic",
    "pytest-dev/pytest",
    "pypa/pip",
    "encode/httpx",
    "django/django",
    "fastapi/fastapi",
    "pallets/werkzeug",
    "pallets/click",
    "celery/celery",
    "sqlalchemy/sqlalchemy",
    "aio-libs/aiohttp",
    "urllib3/urllib3",
    "boto/boto3",
    "aws/aws-cli",
}

// depBumpRe extracts package and version info from Dependabot PR titles.
var depBumpRe = regexp.MustCompile(
	`(?i)bump (?P<pkg>[\w\-\.\/]+) from (?P<from>[\d\.]+) to (?P<to>[\d\.]+)`,
)

// ghPR represents the GitHub Pull Requests API response shape
type ghPR struct {
    Number   int    `json:"number"`
    Title    string `json:"title"`
    MergedAt *string `json:"merged_at"`
    User     struct{ Login string `json:"login"` } `json:"user"`
    Head     struct{ Ref string `json:"ref"` } `json:"head"`
}

type ghEvent struct {
	Type  string `json:"type"`
	Actor struct{ Login string `json:"login"` } `json:"actor"`
	Repo  struct{ Name string `json:"name"` } `json:"repo"`
	Payload struct {
		Action      string `json:"action"`
		PullRequest struct {
			Number   int    `json:"number"`
			Title    string `json:"title"`
			Merged   bool   `json:"merged"`
			MergedAt string `json:"merged_at"`
			Head     struct{ Ref string `json:"ref"` } `json:"head"`
		} `json:"pull_request"`
	} `json:"payload"`
}

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	
	metrics.Init(getenv("METRICS_PORT", "2112"))
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	brokers := getenv("KAFKA_BROKERS", "localhost:9092")
	redisAddr := getenv("REDIS_ADDR", "localhost:6379")
	token := os.Getenv("GITHUB_TOKEN")
	if token == "" {
		log.Warn().Msg("GITHUB_TOKEN not set — rate limited to 60 req/hour")
	}
	
	producer, err := sharedkafka.NewProducer(brokers)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create kafka producer")
	}
	defer producer.Close()
	
	rdb := redis.NewClient(&redis.Options{Addr: redisAddr})
	
	log.Info().
		Int("repos", len(targetRepos)).
		Str("redis", redisAddr).
		Msg("github events poller starting")
	
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()
	
	pollAll(rdb, producer, token)
	for range ticker.C {
		pollAll(rdb, producer, token)
	}
	
}

// pollAll iterates through all target repos sequentially, fetching events for
// each. Repos with no new activity since the last poll return HTTP 304 and
// cost nothing against the GitHub rate limit.
func pollAll(rdb *redis.Client, producer *sharedkafka.Producer, token string) {
	ctx := context.Background()
	total := 0
	skipped := 0
	
	for _, repo := range targetRepos {
		etag := readEtag(ctx, rdb, repo)
		
		events, newETag, err := fetchEvents(repo, token, etag)
		if err != nil {
			log.Error().Err(err).Str("repo", repo).Msg("failed to fetch events")
			continue
		}
		
		if events == nil {
			skipped++
			continue
		}
		
		if newETag != "" {
			writeETag(ctx, rdb, repo, newETag)
		}
		
		for _, event := range events {
			dep := parseDepChange(event)
			if dep == nil {
				continue
			}
			payload, _ := json.Marshal(dep)
			if err := producer.Publish(depsTopic, dep.ServiceID, payload); err != nil {
				log.Error().Err(err).Str("repo", repo).Msg("failed to publish dependency change")
				continue
			}
			total++
		}
	}
	
	log.Info().
		Int("published", total).
		Int("skipped_304", skipped).
		Int("active", len(targetRepos)-skipped).
		Msg("github poll complete")
}

// fetchEvents fetches the event list for one repo.
//
// GitHub ETag behaviour:
//   - First request (no ETag): returns 200 + full event list + ETag header
//   - Subsequent requests (ETag sent in If-None-Match): returns either
//       304 Not Modified — nothing changed, empty body, no rate limit token consumed
//       200 OK           — new events available, fresh ETag in response header
func fetchEvents(repo, token, etag string) ([]ghEvent, string, error) {
	req, _ := http.NewRequest(
		http.MethodGet,
		"https://api.github.com/repos/"+repo+"/pulls?state=closed&per_page=100&sort=updated&direction=desc",
		nil,
	)
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == http.StatusNotModified {
		return nil, "", nil
	}
	
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
		log.Warn().
			Str("repo", repo).
			Int("status", resp.StatusCode).
			Msg("github rate limit exceeded")
	}
	
	if resp.StatusCode != http.StatusOK {
		return nil, "", nil
	}
	
	newETag := resp.Header.Get("ETag")
	body, _ := io.ReadAll(resp.Body)
	
	var prs []ghPR
	if err := json.Unmarshal(body, &prs); err != nil {
		return nil, "", err
	}
	
	events := make([]ghEvent, 0, len(prs))
	for _, pr := range prs {
		if pr.MergedAt == nil {
			continue
		}
		
		events = append(events, ghEvent{
			Type: "PullRequestEvent",
			Actor: struct{ Login string `json:"login"` }{
				Login: pr.User.Login,
			},
			Repo: struct{ Name string `json:"name"`}{
				Name: repo,
			},
			Payload: struct {
                Action      string `json:"action"`
                PullRequest struct {
                    Number   int    `json:"number"`
                    Title    string `json:"title"`
                    Merged   bool   `json:"merged"`
                    MergedAt string `json:"merged_at"`
                    Head     struct{ Ref string `json:"ref"` } `json:"head"`
                } `json:"pull_request"`
            }{
                Action: "merged",
                PullRequest: struct {
                    Number   int    `json:"number"`
                    Title    string `json:"title"`
                    Merged   bool   `json:"merged"`
                    MergedAt string `json:"merged_at"`
                    Head     struct{ Ref string `json:"ref"` } `json:"head"`
                }{
                    Number:   pr.Number,
                    Title:    pr.Title,
                    Merged:   true,
                    MergedAt: *pr.MergedAt,
                    Head:     struct{ Ref string `json:"ref"` }{Ref: pr.Head.Ref},
                },
            },
		})
	}
	return events, newETag, nil
}

// readETag returns the stored ETag for a repo from Redis.
// Returns an empty string if no ETag has been stored yet (first poll).
func readEtag(ctx context.Context, rdb *redis.Client, repo string) string {
	val, err := rdb.Get(ctx, etagKeyPrefix+repo).Result()
	if err != nil {
		return ""
	}
	return val
}

// writeETag stores the ETag for a repo in Redis with no expiry.
// ETags remain valid indefinitely — GitHub invalidates them server-side
// when the repo's event list changes.
func writeETag(ctx context.Context, rdb *redis.Client, repo, etag string) {
	if err := rdb.Set(ctx, etagKeyPrefix+repo, etag, 0).Err(); err != nil {
		log.Error().Err(err).Str("repo", repo).Msg("failed to write etag")
	}
}

// parseDepChange returns a DependencyChangeEvent for a merged Dependabot/Renovate PR
func parseDepChange(event ghEvent) *schemas.DependencyChangeEvent {
	if event.Type != "PullRequestEvent" || event.Payload.Action != "merged" {
		return nil
	}

	pr := event.Payload.PullRequest

	login := strings.ToLower(event.Actor.Login)
	if !strings.Contains(login, "dependabot") && !strings.Contains(login, "renovate") {
		return nil
	}

	eco := schemas.EcosystemFromBranch(pr.Head.Ref)
	if eco == "" {
		return nil
	}

	pkg, fromVer, toVer := parseBumpTitle(pr.Title)
	if pkg == "" || toVer == "" {
		return nil
	}

	mergedAt, err := time.Parse(time.RFC3339, pr.MergedAt)
	if err != nil {
		mergedAt = time.Now().UTC()
	}

	return &schemas.DependencyChangeEvent{
		EventID:      uuid.NewString(),
		Source:       "github_events_api",
		Repo:         event.Repo.Name,
		ServiceID:    event.Repo.Name,
		PRNumber:     pr.Number,
		Author:       event.Actor.Login,
		Ecosystem:    eco,
		ManifestFile: schemas.ManifestForEcosystem(eco),
		Updated: []schemas.DependencyUpdate{
			{Package: pkg, FromVersion: fromVer, ToVersion: toVer},
		},
		OccurredAt: mergedAt,
		IngestedAt: time.Now().UTC(),
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