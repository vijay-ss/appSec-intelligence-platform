FROM golang:1.22-bookworm AS builder

WORKDIR /build

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY shared/ ./shared/
COPY nvd-poller/ ./nvd-poller/

RUN CGO_ENABLED=1 GOOS=linux \
    go build -ldflags="-s -w" -o /nvd-poller ./nvd-poller/


FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    librdkafka1 \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY --from=builder /nvd-poller /usr/local/bin/nvd-poller

RUN useradd -r -s /bin/false appuser
USER appuser

ENV KAFKA_BROKERS=redpanda:9092
ENV REDIS_ADDR=redis:6379
ENV NVD_POLL_INTERVAL_SECONDS=300
ENV METRICS_PORT=2112

EXPOSE 2112

ENTRYPOINT ["nvd-poller"]