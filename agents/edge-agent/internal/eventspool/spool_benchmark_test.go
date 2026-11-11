package eventspool

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
)

// AppendBatch, Flush (read + ack) and Stats at a steady
// pending depth. Each iteration keeps the pending depth constant.

func backlogSpool(b *testing.B, backlog int) (*Spool, *int) {
	b.Helper()
	root := filepath.Join(b.TempDir(), "spool")
	if resolved, err := filepath.EvalSymlinks(filepath.Dir(root)); err == nil {
		root = filepath.Join(resolved, "spool")
	}
	spool, err := New(memoryTestConfig(root))
	if err != nil {
		b.Fatal(err)
	}
	next := 0
	for next < backlog {
		benchmarkAppend(b, spool, &next, min(1000, backlog-next))
	}
	return spool, &next
}

func benchmarkAppend(b *testing.B, spool *Spool, next *int, count int) {
	envelopes := make([]Envelope, count)
	for index := range envelopes {
		envelopes[index] = memoryTestEvent(*next)
		*next++
	}
	if _, err := spool.AppendBatch(context.Background(), envelopes); err != nil {
		b.Fatal(err)
	}
}

func benchmarkFlush(b *testing.B, spool *Spool, count int) {
	result, err := spool.Flush(context.Background(), ackAllPublisher{}, count)
	if err != nil || result.Published != count {
		b.Fatalf("flush published=%d err=%v", result.Published, err)
	}
}

var benchmarkBacklogs = []int{0, 10000}

func BenchmarkSpoolAppendBatch100(b *testing.B) {
	for _, backlog := range benchmarkBacklogs {
		b.Run(fmt.Sprintf("backlog=%d", backlog), func(b *testing.B) {
			spool, next := backlogSpool(b, backlog)
			b.ResetTimer()
			for range b.N {
				benchmarkAppend(b, spool, next, 100)
				b.StopTimer()
				benchmarkFlush(b, spool, 100)
				b.StartTimer()
			}
		})
	}
}

func BenchmarkSpoolFlushAck100(b *testing.B) {
	for _, backlog := range benchmarkBacklogs {
		b.Run(fmt.Sprintf("backlog=%d", backlog), func(b *testing.B) {
			spool, next := backlogSpool(b, backlog)
			b.ResetTimer()
			for range b.N {
				b.StopTimer()
				benchmarkAppend(b, spool, next, 100)
				b.StartTimer()
				benchmarkFlush(b, spool, 100)
			}
		})
	}
}

func BenchmarkSpoolAck1(b *testing.B) {
	for _, backlog := range benchmarkBacklogs {
		b.Run(fmt.Sprintf("backlog=%d", backlog), func(b *testing.B) {
			spool, next := backlogSpool(b, backlog)
			acked := uint64(0)
			b.ResetTimer()
			for range b.N {
				b.StopTimer()
				benchmarkAppend(b, spool, next, 1)
				acked++
				b.StartTimer()
				if err := spool.Ack(acked, fmt.Sprintf("evt-%012d", acked-1)); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkSpoolStats(b *testing.B) {
	for _, backlog := range benchmarkBacklogs {
		b.Run(fmt.Sprintf("backlog=%d", backlog), func(b *testing.B) {
			spool, _ := backlogSpool(b, backlog)
			b.ResetTimer()
			for range b.N {
				if _, err := spool.Stats(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
