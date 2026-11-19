//go:build integration

package gateway

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
)

// A gateway after a reconnect wave:
// a node reconnects while its old session still has a pull waiting on the
// per-node consumer (MaxWaiting 1). The new session's first pulls were
// answered "Exceeded MaxWaiting" and counted as delivery failures (warn,
// 1..3/6, the session ends at 6). The old session stops (cancel + Close)
// right after; the new session's Next must wait that out instead of failing,
// and still deliver what is published afterwards.
func TestSupersededSessionPullDoesNotFailTheNextSession(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is required")
	}
	connection := connectIntegrationNATS(t, natsURL)
	t.Cleanup(connection.Close) // after the stream cleanups below (LIFO)
	js, err := connection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	const operation = 2 * time.Second
	suffix := func() string { return strings.ReplaceAll(uuid.NewString(), "-", "") }
	dropStreams := func(names ...string) {
		for _, name := range names {
			t.Cleanup(func() { _ = js.DeleteStream(name) })
		}
	}
	sources := map[string]func(t *testing.T) func(context.Context) (session, error){
		"securityBans": func(t *testing.T) func(context.Context) (session, error) {
			s := suffix()
			config := DefaultNATSSecurityBanBusConfig()
			config.CommandStream, config.StatusStream = "SBC_"+s, "SBS_"+s
			config.CommandSubjectPrefix, config.StatusSubjectPrefix = "cdnca.test."+s+".sbc", "cdnca.test."+s+".sbs"
			config.ConsumerPrefix, config.OperationTimeout = "sb_"+s, operation
			bus, err := NewNATSSecurityBanBus(ctx, connection, config)
			if err != nil {
				t.Fatal(err)
			}
			dropStreams(config.CommandStream, config.StatusStream)
			return func(ctx context.Context) (session, error) {
				sub, err := bus.SubscribeSecurityBans(ctx, testNodeID)
				if err != nil {
					return session{}, err
				}
				return session{next: func(ctx context.Context) error { _, err := sub.Next(ctx); return err }, close: sub.Close}, nil
			}
		},
		"installationBan": func(t *testing.T) func(context.Context) (session, error) {
			s := suffix()
			config := DefaultNATSInstallationBanBusConfig()
			config.CommandStream, config.StatusStream = "IBC_"+s, "IBS_"+s
			config.CommandSubjectPrefix, config.StatusSubjectPrefix = "cdnca.test."+s+".ibc", "cdnca.test."+s+".ibs"
			config.ConsumerPrefix, config.OperationTimeout = "ib_"+s, operation
			bus, err := NewNATSInstallationBanBus(ctx, connection, config)
			if err != nil {
				t.Fatal(err)
			}
			dropStreams(config.CommandStream, config.StatusStream)
			return func(ctx context.Context) (session, error) {
				sub, err := bus.SubscribeInstallationBan(ctx, testNodeID)
				if err != nil {
					return session{}, err
				}
				return session{next: func(ctx context.Context) error { _, err := sub.Next(ctx); return err }, close: sub.Close}, nil
			}
		},
		"signerTrust": func(t *testing.T) func(context.Context) (session, error) {
			s := suffix()
			config := DefaultNATSSignerTrustBusConfig()
			config.CommandStream, config.StatusStream = "STC_"+s, "STS_"+s
			config.CommandSubjectPrefix, config.StatusSubjectPrefix = "cdnca.test."+s+".stc", "cdnca.test."+s+".sts"
			config.ConsumerPrefix, config.OperationTimeout = "st_"+s, operation
			bus, err := NewNATSSignerTrustBus(ctx, connection, config)
			if err != nil {
				t.Fatal(err)
			}
			dropStreams(config.CommandStream, config.StatusStream)
			return func(ctx context.Context) (session, error) {
				sub, err := bus.SubscribeSignerTrust(ctx, testNodeID)
				if err != nil {
					return session{}, err
				}
				return session{next: func(ctx context.Context) error { _, err := sub.Next(ctx); return err }, close: sub.Close}, nil
			}
		},
		"sched302": func(t *testing.T) func(context.Context) (session, error) {
			bus, err := NewNATSSched302Bus(ctx, connection, operation)
			if err != nil {
				t.Fatal(err)
			}
			return func(ctx context.Context) (session, error) {
				sub, err := bus.SubscribeSched302(ctx, testNodeID)
				if err != nil {
					return session{}, err
				}
				return session{next: func(ctx context.Context) error { _, err := sub.Next(ctx); return err }, close: sub.Close}, nil
			}
		},
	}
	for name, source := range sources {
		t.Run(name, func(t *testing.T) {
			subscribe := source(t)
			assertNextSessionWaits(t, ctx, subscribe)
		})
	}
	t.Run("autoDefense", func(t *testing.T) {
		s := suffix()
		config := DefaultNATSAutoDefenseBusConfig()
		config.CommandStream, config.ReceiptStream, config.ReportStream = "ADC_"+s, "ADR_"+s, "ADP_"+s
		config.CommandSubjectPrefix = "cdnca.test." + s + ".commands"
		config.ReceiptSubjectPrefix = "cdnca.test." + s + ".receipts"
		config.ReportSubjectPrefix = "cdnca.test." + s + ".reports"
		config.ConsumerPrefix, config.OperationTimeout = "autodefense_"+s, operation
		bus, err := NewNATSAutoDefenseBus(ctx, connection, config)
		if err != nil {
			t.Fatal(err)
		}
		dropStreams(config.CommandStream, config.ReceiptStream, config.ReportStream)
		old, err := bus.SubscribeAutoDefense(ctx, testNodeID)
		if err != nil {
			t.Fatal(err)
		}
		oldCtx, stopOld := context.WithCancel(ctx)
		oldDone := make(chan struct{})
		go func() { _, _ = old.Next(oldCtx); close(oldDone) }()
		time.Sleep(200 * time.Millisecond) // the old pull is waiting on the server
		current, err := bus.SubscribeAutoDefense(ctx, testNodeID)
		if err != nil {
			t.Fatal(err)
		}
		defer current.Close()
		type result struct {
			delivery AutoDefenseDelivery
			err      error
		}
		got := make(chan result, 1)
		go func() {
			delivery, err := current.Next(ctx)
			got <- result{delivery, err}
		}()
		time.Sleep(300 * time.Millisecond)
		stopOld()
		_ = old.Close()
		<-oldDone
		part := testAutoDefenseCommand(t, testNodeID, 1)
		payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(part)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := js.Publish(config.CommandSubjectPrefix+"."+testNodeID, payload, nats.ExpectStream(config.CommandStream)); err != nil {
			t.Fatal(err)
		}
		select {
		case r := <-got:
			if r.err != nil || !proto.Equal(r.delivery.Command(), part) {
				t.Fatalf("next session after a superseded pull: %v", r.err)
			}
		case <-time.After(3 * operation):
			t.Fatal("next session did not get the part")
		}
	})
}

// session is one node session's pull on a per-node consumer.
type session struct {
	next  func(context.Context) error
	close func() error
}

// assertNextSessionWaits: with nothing published, the new session's Next
// overlapping the old session's pull ends only with its own context.
func assertNextSessionWaits(t *testing.T, ctx context.Context, subscribe func(context.Context) (session, error)) {
	t.Helper()
	old, err := subscribe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	oldCtx, stopOld := context.WithCancel(ctx)
	oldDone := make(chan struct{})
	go func() { _ = old.next(oldCtx); close(oldDone) }()
	time.Sleep(200 * time.Millisecond)
	current, err := subscribe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer current.close()
	nextCtx, stopNext := context.WithTimeout(ctx, 3*time.Second)
	defer stopNext()
	got := make(chan error, 1)
	go func() { got <- current.next(nextCtx) }()
	time.Sleep(300 * time.Millisecond)
	stopOld()
	_ = old.close()
	<-oldDone
	if err := <-got; !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("next session failed while the old pull was still waiting: %v", err)
	}
}

// The per-node command consumers (MaxWaiting from the
// bus configuration, 1 here to force it) wait out a superseded session's
// pull the same way.
func TestSupersededSessionPullDoesNotFailTheCommandSessions(t *testing.T) {
	natsURL := os.Getenv("CDNCA_TEST_NATS_URL")
	if natsURL == "" {
		t.Skip("CDNCA_TEST_NATS_URL is required")
	}
	connection := connectIntegrationNATS(t, natsURL)
	t.Cleanup(connection.Close) // after the stream cleanups below (LIFO)
	js, err := connection.JetStream(nats.MaxWait(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	config := DefaultNATSCommandBusConfig()
	config.MaxWaiting, config.OperationTimeout = 1, 2*time.Second
	for name, subjects := range map[string][]string{
		config.CommandStream: {"cdnca.agent.commands.>"}, config.FirewallCommandStream: {config.FirewallCommandSubjectPrefix + ".>"},
	} {
		if _, err := js.AddStream(&nats.StreamConfig{Name: name, Subjects: subjects, Storage: nats.FileStorage}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = js.DeleteStream(name) })
	}
	bus, err := NewNATSCommandBus(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := NewNATSCacheCommandBus(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	upgrade, err := NewNATSUpgradeCommandBus(connection, config)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	wrap := func(next func(context.Context) error, close func() error) session {
		return session{next: next, close: close}
	}
	sources := map[string]func(context.Context) (session, error){
		"commands": func(ctx context.Context) (session, error) {
			s, err := bus.Subscribe(ctx, testNodeID)
			if err != nil {
				return session{}, err
			}
			return wrap(func(ctx context.Context) error { _, err := s.Next(ctx); return err }, s.Close), nil
		},
		"firewall": func(ctx context.Context) (session, error) {
			s, err := bus.SubscribeFirewall(ctx, testNodeID)
			if err != nil {
				return session{}, err
			}
			return wrap(func(ctx context.Context) error { _, err := s.Next(ctx); return err }, s.Close), nil
		},
		"overlay": func(ctx context.Context) (session, error) {
			s, err := bus.SubscribeOverlay(ctx, testNodeID)
			if err != nil {
				return session{}, err
			}
			return wrap(func(ctx context.Context) error { _, err := s.Next(ctx); return err }, s.Close), nil
		},
		"drain": func(ctx context.Context) (session, error) {
			s, err := bus.SubscribeDrain(ctx, testNodeID)
			if err != nil {
				return session{}, err
			}
			return wrap(func(ctx context.Context) error { _, err := s.Next(ctx); return err }, s.Close), nil
		},
		"portTransitions": func(ctx context.Context) (session, error) {
			s, err := bus.SubscribePortTransitions(ctx, testNodeID)
			if err != nil {
				return session{}, err
			}
			return wrap(func(ctx context.Context) error { _, err := s.Next(ctx); return err }, s.Close), nil
		},
		"cache": func(ctx context.Context) (session, error) {
			s, err := cache.SubscribeCache(ctx, testNodeID)
			if err != nil {
				return session{}, err
			}
			return wrap(func(ctx context.Context) error { _, err := s.Next(ctx); return err }, s.Close), nil
		},
		"upgrade": func(ctx context.Context) (session, error) {
			s, err := upgrade.SubscribeUpgrade(ctx, testNodeID)
			if err != nil {
				return session{}, err
			}
			return wrap(func(ctx context.Context) error { _, err := s.Next(ctx); return err }, s.Close), nil
		},
	}
	for name, subscribe := range sources {
		t.Run(name, func(t *testing.T) { assertNextSessionWaits(t, ctx, subscribe) })
	}
}
