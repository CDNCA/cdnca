package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/nats-io/nats.go"
)

const (
	ingestStream          = "ANALYTICS_INGEST_V1"
	ingestDurable         = "control_api_analytics_ingest_v1"
	isolationStream       = "ANALYTICS_ISOLATION_V1"
	ccCoordinationStream  = "SECURITY_CC_COORDINATION_V1"
	connectionsStream     = "CONNECTIONS_INGEST_V1"
	connectionsDurable    = "control_api_connections"
	connectionsDeadStream = "CONNECTIONS_DEAD_V1"
	l4SessionsStream      = "L4_SESSIONS_INGEST_V1"
	stateBucket           = "AISTATE_2dcd3c381ead92f3"
	leaseBucket           = "AILEASE_2dcd3c381ead92f3"
	evidenceBucket        = "AIEVIDENCE_2dcd3c381ead92f3"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	url := os.Getenv("NATS_URL")
	user := os.Getenv("NATS_TEST_USERNAME")
	password := os.Getenv("NATS_TEST_PASSWORD")
	mode := os.Getenv("NATS_TEST_MODE")
	if url == "" || user == "" || password == "" || (mode != "runtime" && mode != "publisher") {
		return errors.New("ACL probe configuration is incomplete")
	}
	connection, err := nats.Connect(
		url, nats.UserInfo(user, password), nats.Timeout(3*time.Second), nats.NoReconnect(),
		nats.ErrorHandler(func(*nats.Conn, *nats.Subscription, error) {}),
	)
	if err != nil {
		return fmt.Errorf("connect ACL probe: %w", err)
	}
	defer connection.Close()
	jetstream, err := connection.JetStream(nats.MaxWait(3 * time.Second))
	if err != nil {
		return fmt.Errorf("open JetStream ACL probe: %w", err)
	}
	if mode == "publisher" {
		return probePublisher(jetstream)
	}
	return probeRuntime(jetstream)
}

func probePublisher(jetstream nats.JetStreamContext) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, stream := range []string{ingestStream, ccCoordinationStream, connectionsStream, l4SessionsStream} {
		info, err := jetstream.StreamInfo(stream, nats.Context(ctx))
		if err != nil {
			return fmt.Errorf("publisher stream info %s: %w", stream, err)
		}
		if info == nil || info.Config.Name != stream {
			return fmt.Errorf("publisher stream info %s returned an invalid response", stream)
		}
	}
	message := nats.NewMsg("cdnca.analytics.ingest.v1.acl-node")
	message.Header.Set(nats.MsgIdHdr, "acl-publisher-positive")
	message.Data = []byte(`{"acl":"publisher"}`)
	if _, err := jetstream.PublishMsg(message); err != nil {
		return fmt.Errorf("publisher ingest permission: %w", err)
	}
	connectionsMessage := nats.NewMsg("cdnca.connections.v1.acl-installation.acl-receipt")
	connectionsMessage.Header.Set(nats.MsgIdHdr, "acl-publisher-connections")
	connectionsMessage.Header.Set(nats.ExpectedLastSubjSeqHdr, "0")
	connectionsMessage.Data = []byte(`{"acl":"publisher-connections"}`)
	ack, err := jetstream.PublishMsg(connectionsMessage, nats.Context(ctx))
	if err != nil {
		return fmt.Errorf("publisher connections permission: %w", err)
	}
	if ack == nil || ack.Stream != connectionsStream || ack.Sequence == 0 {
		return errors.New("publisher connections acknowledgement is invalid")
	}
	deniedCtx, deniedCancel := context.WithTimeout(context.Background(), time.Second)
	_, deniedErr := jetstream.StreamInfo(isolationStream, nats.Context(deniedCtx))
	deniedCancel()
	if deniedErr == nil {
		return fmt.Errorf("publisher stream info unexpectedly allowed on %s", isolationStream)
	}
	if err := expectPublishDenied(jetstream, "cdnca.analytics.unrelated.v1", []byte("denied")); err != nil {
		return err
	}
	if err := expectPublishDenied(jetstream, "cdnca.analytics.isolation.v1", []byte("denied")); err != nil {
		return err
	}
	if err := expectPublishDenied(jetstream, "cdnca.connections.dead.v1", []byte("denied")); err != nil {
		return err
	}
	return expectManagementDenied(jetstream)
}

func probeRuntime(jetstream nats.JetStreamContext) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, stream := range []string{ingestStream, isolationStream, connectionsStream, connectionsDeadStream, "KV_" + stateBucket, "KV_" + leaseBucket, "KV_" + evidenceBucket} {
		if _, err := jetstream.StreamInfo(stream, nats.Context(ctx)); err != nil {
			return fmt.Errorf("runtime stream info %s: %w", stream, err)
		}
	}
	if _, err := jetstream.ConsumerInfo(ingestStream, ingestDurable, nats.Context(ctx)); err != nil {
		return fmt.Errorf("runtime consumer info: %w", err)
	}
	if _, err := jetstream.ConsumerInfo(connectionsStream, connectionsDurable, nats.Context(ctx)); err != nil {
		return fmt.Errorf("runtime connections consumer info: %w", err)
	}
	for _, bucket := range []string{stateBucket, leaseBucket, evidenceBucket} {
		store, err := jetstream.KeyValue(bucket)
		if err != nil {
			return fmt.Errorf("runtime open KV %s: %w", bucket, err)
		}
		key := "acl_probe"
		revision, err := store.Create(key, []byte("one"))
		if err != nil {
			return fmt.Errorf("runtime KV create %s: %w", bucket, err)
		}
		if _, err = store.Get(key); err != nil {
			return fmt.Errorf("runtime KV get %s: %w", bucket, err)
		}
		if _, err = store.Update(key, []byte("two"), revision); err != nil {
			return fmt.Errorf("runtime KV update %s: %w", bucket, err)
		}
		keys, err := store.Keys(nats.Context(ctx))
		if err != nil || len(keys) == 0 {
			return fmt.Errorf("runtime KV keys %s: %w", bucket, err)
		}
		if err := store.Delete(key); err != nil {
			return fmt.Errorf("runtime KV key delete %s: %w", bucket, err)
		}
	}
	if _, err := jetstream.Publish("cdnca.analytics.isolation.v1", []byte("runtime-isolation"), nats.Context(ctx)); err != nil {
		return fmt.Errorf("runtime isolation publish: %w", err)
	}
	if err := expectPublishDenied(jetstream, "cdnca.analytics.ingest.v1.runtime-denied", []byte("denied")); err != nil {
		return err
	}
	subscription, err := jetstream.PullSubscribe(
		"cdnca.analytics.ingest.v1.*", ingestDurable, nats.Bind(ingestStream, ingestDurable),
	)
	if err != nil {
		return fmt.Errorf("runtime bind ingest durable: %w", err)
	}
	messages, err := subscription.Fetch(1, nats.MaxWait(2*time.Second))
	if err != nil || len(messages) != 1 {
		return fmt.Errorf("runtime fetch ingest: %w", err)
	}
	metadata, err := messages[0].Metadata()
	if err != nil {
		return fmt.Errorf("runtime ingest metadata: %w", err)
	}
	if _, err := jetstream.GetMsg(ingestStream, metadata.Sequence.Stream, nats.Context(ctx)); err != nil {
		return fmt.Errorf("runtime ingest message get: %w", err)
	}
	if err := messages[0].AckSync(nats.Context(ctx)); err != nil {
		return fmt.Errorf("runtime ingest ack: %w", err)
	}
	connectionsSubscription, err := jetstream.PullSubscribe(
		"cdnca.connections.v1.*.*", connectionsDurable, nats.Bind(connectionsStream, connectionsDurable),
	)
	if err != nil {
		return fmt.Errorf("runtime bind connections durable: %w", err)
	}
	connectionsMessages, err := connectionsSubscription.Fetch(1, nats.MaxWait(2*time.Second))
	if err != nil || len(connectionsMessages) != 1 {
		return fmt.Errorf("runtime fetch connections: %w", err)
	}
	if err := connectionsMessages[0].AckSync(nats.Context(ctx)); err != nil {
		return fmt.Errorf("runtime connections ack: %w", err)
	}
	deadMessage := nats.NewMsg("cdnca.connections.dead.v1")
	deadMessage.Header.Set(nats.MsgIdHdr, "acl-runtime-connections-dead")
	deadMessage.Data = []byte(`{"acl":"runtime-connections-dead"}`)
	deadAck, err := jetstream.PublishMsg(deadMessage, nats.Context(ctx))
	if err != nil {
		return fmt.Errorf("runtime connections dead-letter publish: %w", err)
	}
	if deadAck == nil || deadAck.Stream != connectionsDeadStream || deadAck.Sequence == 0 {
		return errors.New("runtime connections dead-letter acknowledgement is invalid")
	}
	if _, err := jetstream.GetMsg(connectionsDeadStream, deadAck.Sequence, nats.Context(ctx)); err != nil {
		return fmt.Errorf("runtime connections dead-letter get: %w", err)
	}
	if err := expectPublishDenied(jetstream, "cdnca.connections.v1.runtime-denied.receipt", []byte("denied")); err != nil {
		return err
	}
	return expectManagementDenied(jetstream)
}

func expectPublishDenied(jetstream nats.JetStreamContext, subject string, payload []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := jetstream.Publish(subject, payload, nats.Context(ctx)); err == nil {
		return fmt.Errorf("publish unexpectedly allowed on %s", subject)
	}
	return nil
}

func expectManagementDenied(jetstream nats.JetStreamContext) error {
	withTimeout := func(run func(nats.ContextOpt) error) error {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		return run(nats.Context(ctx))
	}
	checks := []struct {
		name string
		run  func() error
	}{
		{"add", func() error {
			return withTimeout(func(option nats.ContextOpt) error {
				_, err := jetstream.AddStream(&nats.StreamConfig{Name: "ACL_FORBIDDEN", Subjects: []string{"acl.forbidden"}}, option)
				return err
			})
		}},
		{"update", func() error {
			return withTimeout(func(option nats.ContextOpt) error {
				_, err := jetstream.UpdateStream(&nats.StreamConfig{Name: ingestStream, Subjects: []string{"cdnca.analytics.ingest.v1.*"}}, option)
				return err
			})
		}},
		{"delete", func() error {
			return withTimeout(func(option nats.ContextOpt) error { return jetstream.DeleteStream(ingestStream, option) })
		}},
		{"purge", func() error {
			return withTimeout(func(option nats.ContextOpt) error { return jetstream.PurgeStream(ingestStream, option) })
		}},
	}
	for _, check := range checks {
		if err := check.run(); err == nil {
			return fmt.Errorf("JetStream management %s unexpectedly allowed", check.name)
		}
	}
	return nil
}
