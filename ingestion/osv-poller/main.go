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
	"bytes"
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
	osvPageSize      = 1000
	osvAPIDelay      = 200 * time.Millisecond
)

var targetEcosystems = []string{"PyPI", "npm", "Maven", "Go", "crates.io", "RubyGems"}

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	metrics.Init(getenv("METRICS_PORT", "2112"))

	brokers := getenv("KAFKA_BROKERS", "localhost:9092")
	redisAddr := getenv("REDIS_ADDR", "localhost:6379")
	pollSecs := getenvInt("OSV_POLL_INTERVAL_SECONDS", 600)

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