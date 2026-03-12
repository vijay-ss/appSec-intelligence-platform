// NVD Poller — polls the NIST National Vulnerability Database every 5 minutes.
// Publishes normalised VulnerabilityEvents to Kafka topic: vulns.nvd.raw
//
// NVD is used for CVSS scores and CWE classification only.
// OSV (osv-poller) provides the package-level version ranges used in the Flink join.
//
// Rate limits: 50 req/30s with API key (free), 5 req/30s without.
// Register for a free key at: https://nvd.nist.gov/developers/request-an-api-key
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
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
	nvdBaseURL   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	nvdCursorKey = "nvd:cursor:last_pub_date"
	nvdTopic     = "vulns.nvd.raw"
	nvdTimeLayout = "2006-01-02T15:04:05.000"
)

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	metrics.Init(getenv("METRICS_PORT", "2112"))

	brokers := getenv("KAFKA_BROKERS", "localhost:9092")
	redisAddr := getenv("REDIS_ADDR", "localhost:6379")
	apiKey := os.Getenv("NVD_API_KEY")
	pollSecs := getenvInt("NVD_POLL_INTERVAL_SECONDS", 300)

	producer, err := sharedkafka.NewProducer(brokers)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to create kafka producer")
	}
	defer producer.Close()

	rdb := redis.NewClient(&redis.Options{Addr: redisAddr})

	log.Info().
		Str("brokers", brokers).
		Int("poll_interval_seconds", pollSecs).
		Bool("api_key_set", apiKey != "").
		Msg("nvd poller starting")

	interval := time.Duration(pollSecs) * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	poll(rdb, producer, apiKey)
	for range ticker.C {
		poll(rdb, producer, apiKey)
	}
}

func poll(rdb *redis.Client, producer *sharedkafka.Producer, apiKey string) {
	ctx := context.Background()

	cursor, err := rdb.Get(ctx, nvdCursorKey).Result()
	if err == redis.Nil {
		cursor = time.Now().UTC().Add(-24 * time.Hour).Format(nvdTimeLayout)
		log.Info().Str("cursor", cursor).Msg("first run — looking back 24h")
	} else if err != nil {
		log.Error().Err(err).Msg("failed to read cursor from redis")
		return
	}

	endTime := time.Now().UTC().Format(nvdTimeLayout)

	cves, err := fetchCVEs(cursor, endTime, apiKey)
	if err != nil {
		log.Error().Err(err).Msg("nvd fetch failed")
		return
	}

	published := 0
	for _, item := range cves {
		fmt.Println(item)
		event := normalise(item)
		if event == nil {
			continue
		}
		payload, _ := json.Marshal(event)
		if err := producer.Publish(nvdTopic, event.CVEID, payload); err != nil {
			log.Error().Err(err).Str("cve_id", event.CVEID).Msg("publish failed")
			continue
		}
		published++
	}

	_ = rdb.Set(ctx, nvdCursorKey, endTime, 0).Err()

	log.Info().
		Int("fetched", len(cves)).
		Int("published", published).
		Str("window_start", cursor).
		Str("window_end", endTime).
		Msg("nvd poll complete")
}

// ── NVD API response types ────────────────────────────────────────────────────

type nvdResponse struct {
	TotalResults    int       `json:"totalResults"`
	Vulnerabilities []nvdItem `json:"vulnerabilities"`
}

type nvdItem struct {
	CVE struct {
		ID          string `json:"id"`
		Published   string `json:"published"`
		Descriptions []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"descriptions"`
		Metrics struct {
			CVSSV31 []struct {
				CVSSData struct {
					BaseScore float64 `json:"baseScore"`
				} `json:"cvssData"`
			} `json:"cvssMetricV31"`
		} `json:"metrics"`
		Weaknesses []struct {
			Description []struct {
				Value string `json:"value"`
			} `json:"description"`
		} `json:"weaknesses"`
	} `json:"cve"`
}

func fetchCVEs(startDate, endDate, apiKey string) ([]nvdItem, error) {
	url := fmt.Sprintf("%s?pubStartDate=%s&pubEndDate=%s", nvdBaseURL, startDate, endDate)

	req, _ := http.NewRequest(http.MethodGet, url, nil)
	if apiKey != "" {
		req.Header.Set("apiKey", apiKey)
	}

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		log.Warn().Msg("rate limited — sleeping 30s")
		time.Sleep(30 * time.Second)
		return nil, fmt.Errorf("rate limited")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("nvd returned HTTP %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	var result nvdResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return result.Vulnerabilities, nil
}

func normalise(item nvdItem) *schemas.VulnerabilityEvent {
	cve := item.CVE
	if cve.ID == "" {
		return nil
	}

	description := ""
	for _, d := range cve.Descriptions {
		if d.Lang == "en" {
			description = d.Value
			break
		}
	}

	cvssScore := 0.0
	if len(cve.Metrics.CVSSV31) > 0 {
		cvssScore = cve.Metrics.CVSSV31[0].CVSSData.BaseScore
	}

	cweID := ""
	if len(cve.Weaknesses) > 0 && len(cve.Weaknesses[0].Description) > 0 {
		cweID = cve.Weaknesses[0].Description[0].Value
	}

	publishedAt, _ := time.Parse(nvdTimeLayout, cve.Published)

	return &schemas.VulnerabilityEvent{
		EventID:      uuid.NewString(),
		CVEID:        cve.ID,
		Source:       "nvd",
		PublishedAt:  publishedAt,
		IngestedAt:   time.Now().UTC(),
		CVSSScore:    cvssScore,
		SeverityTier: schemas.SeverityFromCVSS(cvssScore),
		CWEID:        cweID,
		Description:  description,
		// NVD CPE strings are not directly usable for package-level joins.
		// Leave package fields empty — OSV provides these.
		AffectedVersions: []string{},
	}
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
