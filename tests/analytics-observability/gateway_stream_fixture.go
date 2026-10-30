package main

import (
	"fmt"
	"os"
	"time"

	"github.com/nats-io/nats.go"
)

func main() {
	if len(os.Args) != 2 {
		panic("NATS URL is required")
	}
	connection, err := nats.Connect(os.Args[1], nats.Timeout(5*time.Second))
	if err != nil {
		panic(err)
	}
	defer connection.Close()
	jetstream, err := connection.JetStream(nats.MaxWait(5 * time.Second))
	if err != nil {
		panic(err)
	}
	for _, config := range []*nats.StreamConfig{
		{
			Name: "SECURITY_CC_COORDINATION_V1", Subjects: []string{"cdnca.security.cccoord.v1.*.*"},
			Retention: nats.WorkQueuePolicy, MaxConsumers: 1, MaxMsgs: 2_000_000, MaxBytes: 2 << 30,
			Discard: nats.DiscardNew, MaxAge: 24 * time.Hour, MaxMsgsPerSubject: -1, MaxMsgSize: 1 << 20,
			Storage: nats.FileStorage, Replicas: 1, Duplicates: 10 * time.Minute,
		},
		{
			Name: "L4_SESSIONS_INGEST_V1", Subjects: []string{"cdnca.l4.sessions.v1.*.*.*"},
			Retention: nats.WorkQueuePolicy, MaxConsumers: 1, MaxMsgs: 5_000_000, MaxBytes: 5 << 30,
			Discard: nats.DiscardNew, MaxAge: 30 * 24 * time.Hour, MaxMsgsPerSubject: -1, MaxMsgSize: 1 << 20,
			Storage: nats.FileStorage, Replicas: 1, Duplicates: 10 * time.Minute,
		},
	} {
		if _, err := jetstream.AddStream(config); err != nil {
			panic(fmt.Errorf("create stream %s: %w", config.Name, err))
		}
	}
}
