package inserter

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// TestChannelConsumerFetchBatch —— Fetch 聚合缓冲内消息（≤64）。
func TestChannelConsumerFetchBatch(t *testing.T) {
	c := NewChannelConsumer(16)
	for i := 0; i < 3; i++ {
		c.Inject(Message{Topic: "flows.raw", Key: []byte{0, 0, 0, 101}, Value: []byte("v")})
	}
	msgs, err := c.Fetch(context.Background())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(msgs) != 3 {
		t.Fatalf("fetched %d, want 3", len(msgs))
	}
	if msgs[0].Topic != "flows.raw" || string(msgs[0].Key) != string([]byte{0, 0, 0, 101}) {
		t.Errorf("message fields wrong: %+v", msgs[0])
	}
}

// TestChannelConsumerFetchBlock —— 无消息时阻塞，ctx 取消返回 ctx.Err。
func TestChannelConsumerFetchBlock(t *testing.T) {
	c := NewChannelConsumer(1)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.Fetch(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want DeadlineExceeded", err)
	}
}

// TestChannelConsumerCommit —— Commit 计数。
func TestChannelConsumerCommit(t *testing.T) {
	c := NewChannelConsumer(4)
	c.Inject(Message{Topic: "a"})
	c.Inject(Message{Topic: "b"})
	msgs, _ := c.Fetch(context.Background())
	if err := c.Commit(context.Background(), msgs); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if got := c.Committed(); got != len(msgs) {
		t.Errorf("committed = %d, want %d", got, len(msgs))
	}
}

// TestChannelConsumerClose —— 关闭后 Fetch=ErrConsumerClosed、Inject 静默、幂等。
func TestChannelConsumerClose(t *testing.T) {
	c := NewChannelConsumer(4)
	if err := c.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := c.Close(); err != nil { // 幂等
		t.Fatalf("double close: %v", err)
	}
	c.Inject(Message{Topic: "x"}) // 必须静默不 panic
	if _, err := c.Fetch(context.Background()); !errors.Is(err, ErrConsumerClosed) {
		t.Fatalf("err = %v, want ErrConsumerClosed", err)
	}
}

// TestChannelConsumerInjectCloseRace —— 并发 Inject/Close 不 panic。
func TestChannelConsumerInjectCloseRace(t *testing.T) {
	c := NewChannelConsumer(8)
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					c.Inject(Message{Topic: "flows.raw"})
				}
			}
		}()
	}
	time.Sleep(20 * time.Millisecond)
	_ = c.Close()
	close(stop)
	wg.Wait()
}
