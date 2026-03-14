// Package kafka provides a shared Kafka producer used by all ingestion services.
package kafka

import (
	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/rs/zerolog/log"
)

type Producer struct {
	client *kafka.Producer
}

func NewProducer(brokers string) (*Producer, error) {
	client, err := kafka.NewProducer(&kafka.ConfigMap{
		"bootstrap.servers": brokers,
		"acks":             "all",
		"enable.idempotence": true,
		"retries":           5,
		"compression.type":  "snappy",
		"linger.ms":         10,
	})
	if err != nil {
		return nil, err
	}

	p := &Producer{client: client}
	
	go func() {
		for e := range client.Events() {
			if msg, ok := e.(*kafka.Message); ok {
				if msg.TopicPartition.Error != nil {
					log.Error().
						Err(msg.TopicPartition.Error).
						Str("topic", *msg.TopicPartition.Topic).
						Msg("kafka delivery failed")
				}
			}
		}
	}()

	return p, nil
}

// Publish serialises a message and delivers it to the given topic.
// key is used for partition routing — use the primary entity ID (e.g. CVE ID).
func (p *Producer) Publish(topic string, key string, value []byte) error {
	return p.client.Produce(&kafka.Message{
		TopicPartition: kafka.TopicPartition{Topic: &topic, Partition: kafka.PartitionAny},
		Key:			[]byte(key),
		Value:          value,
	}, 
	nil)
}

func (p *Producer) Close() {
	p.client.Flush(5000)
	p.client.Close()
}