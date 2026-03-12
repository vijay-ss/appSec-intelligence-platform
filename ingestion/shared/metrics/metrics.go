// Package metrics provides a lightweight Prometheus metrics helper shared
// across all ingestion pollers.
//
// Each poller registers its own metrics on startup. The /metrics endpoint
// is served on :2112 so Prometheus can scrape all pollers independently.
//
// Metrics registered here:
//   - events_published_total{poller, topic}        — Kafka publishes
//   - poll_errors_total{poller}                    — upstream API errors
//   - poll_duration_seconds{poller}                — time per poll cycle
//   - last_successful_poll_timestamp{poller}       — Unix timestamp of last OK poll
package metrics

import (
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	EventsPublished = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "events_published_total",
			Help: " Total number of events published to Kafka.",
		},
		[]string{"poller", "topic"},
	)

	PollErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "poll_errors_total",
			Help: "Total number of upstream API errors encountered by poller.",
		},
		[]string{"poller"},
	)

	PollDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "poll_duration_seconds",
			Help: "Time taken for one complete poll cycle.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"poller"},
	)

	LastSuccessfulPoll = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "last_successful_poll_timestamp",
			Help: "Unix timestamp of the last successful poll cycle.",
		},
		[]string{"poller"},
	)
)


// Init registers all metrics with the default Prometheus registry and starts
// the /metrics HTTP server on the given port (e.g. "2112").
//
// Call once from each poller's main() before the poll loop starts.
func Init(port string) {
	prometheus.MustRegister(
		EventsPublished,
		PollErrors,
		PollDuration,
		LastSuccessfulPoll,
	)

	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "ok")
		})
		if err := http.ListenAndServe(":"+port, mux); err != nil {
			// Non-fatal — pollers work without Prometheus scraping
			_ = err
		}
	}()
}