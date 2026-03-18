FROM golang:1.22-bookworm AS builder

WORKDIR /build

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY shared/ ./shared/
COPY github-events-poller/ ./github-events-poller/

RUN CGO_ENABLED=1 GOOS=linux \
    go build -ldflags="-s -w" -o /github-events-poller ./github-events-poller/


FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    librdkafka1 \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY --from=builder /github-events-poller /usr/local/bin/github-events-poller

RUN useradd -r -s /bin/false appuser
USER appuser

ENV KAFKA_BROKERS=redpanda:9092
ENV GITHUB_POLL_INTERVAL_SECONDS=60
ENV METRICS_PORT=2112

EXPOSE 2112

ENTRYPOINT ["github-events-poller"]