FROM golang:1.22-bookworm AS builder

WORKDIR /build

COPY go.mod ./
COPY go.sum ./
RUN go mod download

COPY shared/ ./shared/
COPY archive-replayer/ ./archive-replayer/

RUN CGO_ENABLED=1 GOOS=linux \
    go build -ldflags="-s -w" -o /archive-replayer ./archive-replayer/


FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    librdkafka1 \
    ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY --from=builder /archive-replayer /usr/local/bin/archive-replayer

RUN useradd -r -s /bin/false appuser
USER appuser

ENV KAFKA_BROKERS=redpanda:9092
ENV METRICS_PORT=2112

# Default: continuous replay from 2024-01-01 with 500ms between events.
# Override these with docker run -e or docker compose environment:
ENV REPLAYER_START_DATE=2024-01-01
ENV REPLAYER_END_DATE=2025-01-01
ENV REPLAYER_MODE=continuous
ENV REPLAYER_DELAY_MS=500

EXPOSE 2112

ENTRYPOINT ["archive-replayer"]
CMD ["--start-date", "2024-01-01", "--end-date", "2025-01-01", "--mode", "continuous", "--delay-ms", "500"]
