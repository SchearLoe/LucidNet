package hub

import "testing"

func drain(c *Client) []Message {
	var out []Message
	for {
		select {
		case m := <-c.Send:
			out = append(out, m)
		default:
			return out
		}
	}
}

// TestPublishZoneFilter —— zone 过滤：订阅端 zone 非空时只收同 zone；0 收全部。
func TestPublishZoneFilter(t *testing.T) {
	h := NewHub()
	all := NewClient(0, 8)
	z1 := NewClient(101, 8)
	h.Subscribe(all)
	h.Subscribe(z1)

	h.Publish(Message{Topic: "alarms", Type: "attack", ZoneID: 101})
	h.Publish(Message{Topic: "alarms", Type: "attack", ZoneID: 202})
	h.Publish(Message{Topic: "bgp.mitigations", Type: "mitigation"}) // zone 0 → 广播

	gotAll, gotZ1 := drain(all), drain(z1)
	if len(gotAll) != 3 {
		t.Fatalf("all client got %d, want 3", len(gotAll))
	}
	if len(gotZ1) != 2 {
		t.Fatalf("zone client got %d, want 2 (own + broadcast)", len(gotZ1))
	}
}

// TestSlowClientDrop —— 慢客户端缓冲满丢弃且不阻塞发布（丢弃计数）。
func TestSlowClientDrop(t *testing.T) {
	h := NewHub()
	slow := NewClient(0, 1)
	h.Subscribe(slow)
	h.Publish(Message{Topic: "alarms"}) // 进缓冲
	h.Publish(Message{Topic: "alarms"}) // 丢弃
	h.Publish(Message{Topic: "alarms"}) // 丢弃
	if got := h.Dropped(); got != 2 {
		t.Fatalf("dropped = %d, want 2", got)
	}
	if got := h.Count(); got != 1 {
		t.Fatalf("count = %d, want 1", got)
	}
}

// TestUnsubscribe —— 注销后不再接收。
func TestUnsubscribe(t *testing.T) {
	h := NewHub()
	c := NewClient(0, 8)
	h.Subscribe(c)
	h.Unsubscribe(c)
	h.Publish(Message{Topic: "alarms"})
	if got := drain(c); len(got) != 0 {
		t.Fatalf("got %d after unsubscribe", len(got))
	}
}
