// bulk_loader.go — Phase 1 of the OSV poller.
//
// Downloads the full OSV vulnerability dataset from Google Cloud Storage,
// publishes every record to Kafka, tracks the highest `modified` timestamp
// seen, and writes it to Redis as the cursor for Phase 2 (incremental polling).
//
// The GCS export is a zip file per ecosystem, updated by OSV every ~6 hours.
// Each zip contains one JSON file per vulnerability, matching the osvVuln type
// defined in main.go. We stream the zip without loading it fully into memory —
// a PyPI all.zip is typically 200–400MB.
//
// Cursor handoff:
//
//	After processing all ecosystems, the highest `modified` timestamp seen
//	is written to Redis as osv:cursor:last_modified. The incremental poller
//	reads this key and passes it as modified_since to the REST API, ensuring
//	no gap between the bulk load and ongoing polling.
//
//	Any record that was updated by OSV between when the zip was generated and
//	when incremental polling starts will be re-processed. The Flink
//	deduplicator handles these overlaps via its 24-hour TTL keyed state.
package main

import (
	"archive/zip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
	"golang.org/x/sync/errgroup"

	sharedkafka "github.com/vijay-ss/appsec-intelligence/ingestion/shared/kafka"
)

func bulkLoadIfNeeded(ctx context.Context, rdb *redis.Client, producer *sharedkafka.Producer) error {
	loaded, _ := rdb.Get(ctx, osvBulkLoadedKey).Result()
	if loaded == "1" {
		log.Info().Msg("osv bulk already loaded - skipping to incremental polling")
		return nil
	}

	log.Info().
		Strs("ecosystems", targetEcosystems).
		Msg("starting osv bulk load from GCS — all ecosystems downloading in parallel")

	type ecoResult struct {
		ecosystem string
		count     int
		maxMod    time.Time
		err       error
	}

	results := make(chan ecoResult, len(targetEcosystems))

	// errgroup manages the goroutine lifecycle. We use the context-aware
	// variant so a GCS outage or context cancellation propagates cleanly.
	// We don't use errgroup's error return — each goroutine sends its own
	// result (including any error) through the channel instead.
	g, gctx := errgroup.WithContext(ctx)

	for _, eco := range targetEcosystems {
		eco := eco
		g.Go(func() error {
			url := fmt.Sprintf("%s/%s/all.zip", osvGCSBase, eco)
			count, maxMod, err := downloadEcosystemZip(gctx, url, eco, producer)
			results <- ecoResult{ecosystem: eco, count: count, maxMod: maxMod, err: err}
			return nil
		})
	}

	go func() {
		g.Wait()
		close(results)
	}()

	var (
		maxModified time.Time
		totalPublished int64
	)
	
	for r := range results {
		if r.err != nil {
			log.Error().
				Err(r.err).
				Str("ecosystem", r.ecosystem).
				Msg("ecosystem bulk download failed — will backfill via incremental polling")
			continue
		}

		log.Info().
			Str("ecosystem", r.ecosystem).
			Int("published", r.count).
			Time("max_modified", r.maxMod).
			Msg("ecosystem bulk load complete")
		
		if r.maxMod.After(maxModified) {
			maxModified = r.maxMod
		}
		totalPublished += int64(r.count)
	}

	if !maxModified.IsZero() {
		cursor := maxModified.UTC().Format(time.RFC3339)
		if err := rdb.Set(ctx, osvCursorKey, cursor, 0).Err(); err != nil {
			log.Error().
				Err(err).
				Str("cursor", cursor).
				Msg("failed to write osv cursor to redis after bulk load")
			return fmt.Errorf("write osv cursor: %w", err)
		}
		log.Info().
			Str("cursor", cursor).
			Msg("osv cursor written - incremental polling will resume from here")
	} else {
		// Every ecosystem failed. Write a 30-day fallback cursor so incremental
		// polling has a safe starting point and backfills everything.
		fallback := time.Now().Add(-30 * 24 * time.Hour).UTC().Format(time.RFC3339)
		_ = rdb.Set(ctx, osvCursorKey, fallback, 0).Err()
		log.Warn().
			Str("cursor", fallback).
			Msg("all ecosystems downlaods failed - using 30-day fallback cursor for incremental polling")
	}

	if err := rdb.Set(ctx, osvBulkLoadedKey, "1", 0).Err(); err != nil {
		return fmt.Errorf("set bulk load flag: %w", err)
	}
	
	log.Info().
		Int64("total_published", totalPublished).
		Msg("osv bulk load complete")
	
	return nil
}

// downloadEcosystemZip downloads the GCS all.zip for one ecosystem to a temp
// file, then reads it entry by entry, normalises each record, and publishes to
// Kafka. Returns the count of published events and the highest modified
// timestamp seen across all records.
func downloadEcosystemZip(ctx context.Context, url, ecosystem string, producer *sharedkafka.Producer) (int, time.Time, error) {
	log.Info().
		Str("url", url).
		Str("ecosystem", ecosystem).
		Msg("downloading ecosystem zip")
	
	tmp, err := os.CreateTemp("", "osv-*.zip")
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	defer tmp.Close()
	
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("build request: %w", err)
	}

	resp, err := (&http.Client{Timeout: 10 * time.Minute}).Do(req)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("download zip: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, time.Time{}, fmt.Errorf("gcs returned HTTP %d for %s", resp.StatusCode, url)
	}

	bytesWritten, err := io.Copy(tmp, resp.Body)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("write temp file: %w", err)
	}

	log.Info().
		Str("ecosystem", ecosystem).
		Int64("bytes", bytesWritten).
		Msg("ecosystem zip downloaded")
	
	zipReader, err := zip.NewReader(tmp, bytesWritten)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("open zip: %w", err)
	}

	var maxModified time.Time
	published := 0
	logEvery := 500

	for _, entry := range zipReader.File {
		if entry.FileInfo().IsDir() {
			continue
		}

		count, entryMax, err := processZipEntry(entry, producer)
		if err != nil {
			log.Warn().
				Err(err).
				Str("file", entry.Name).
				Msg("skipping bad zip entry")
			continue
		}

		if entryMax.After(maxModified) {
			maxModified = entryMax
		}

		published += count

		if published%logEvery < count {
			log.Info().
				Str("ecosystem", ecosystem).
				Int("published", published).
				Msg("bulk load progress")
		}
	}

	return published, maxModified, nil
}

func processZipEntry(entry *zip.File, producer *sharedkafka.Producer) (int, time.Time, error) {
	f, err := entry.Open()
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("open zip entry: %w", err)
	}
	defer f.Close()

	var vuln osvVuln
	if err := json.NewDecoder(f).Decode(&vuln); err != nil {
		return 0, time.Time{}, fmt.Errorf("decode json: %w", err)
	}

	events := normalizeOSV(vuln)
	published := 0

	for _, event := range events {
		payload, _ := json.Marshal(event)
		if err := producer.Publish(osvTopic, event.CVEID, payload); err != nil {
			log.Error().
				Err(err).
				Str("cve_id", event.CVEID).
				Str("file", entry.Name).
				Msg("publish failed during bulk load")
			continue
		}
		published++
	}

	return published, vuln.Modified, nil
}