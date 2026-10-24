package decoder

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

var tplExporter = netip.MustParseAddr("10.0.0.1")

func TestMemTemplateCacheCRUD(t *testing.T) {
	c := NewMemTemplateCache()
	key := TemplateKey{Exporter: tplExporter, ObsDomainID: 42, TemplateID: 1024}
	if _, ok := c.Get(key); ok {
		t.Fatal("empty cache: got hit, want miss")
	}
	c.Put(Template{Key: key, Version: uint8(VersionNetFlowV9), Body: []byte{1, 2, 3}})
	got, ok := c.Get(key)
	if !ok || got.Key != key || len(got.Body) != 3 {
		t.Fatalf("get = (%+v,%v), want hit with 3B body", got, ok)
	}
	if c.Len() != 1 {
		t.Errorf("len = %d, want 1", c.Len())
	}
	c.Delete(key)
	if _, ok := c.Get(key); ok {
		t.Error("after delete: got hit, want miss")
	}
	if c.Len() != 0 {
		t.Errorf("len after delete = %d, want 0", c.Len())
	}
}

func TestMemTemplateCacheLazyExpiry(t *testing.T) {
	// IPFIX 模板活跃期可配、默认 24h 重验证（dd/02 §1 #1）；Get 时惰性过期
	now := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	c := NewMemTemplateCache().WithClock(func() time.Time { return now })
	key := TemplateKey{Exporter: tplExporter, ObsDomainID: 1, TemplateID: 256}

	// v9 语义：ExpiresAt 零值 = 无超时
	c.Put(Template{Key: key, Version: uint8(VersionNetFlowV9), Body: nil})
	if _, ok := c.Get(key); !ok {
		t.Error("v9 no-expiry template: got miss, want hit")
	}

	// IPFIX 语义：过期后 Get 返回 miss 并清除
	c.Put(Template{Key: key, Version: uint8(VersionIPFIX), ExpiresAt: now.Add(24 * time.Hour)})
	if _, ok := c.Get(key); !ok {
		t.Error("before expiry: got miss, want hit")
	}
	later := func() time.Time { return now.Add(25 * time.Hour) }
	c.Put(Template{Key: key, Version: uint8(VersionIPFIX), ExpiresAt: now.Add(24 * time.Hour)})
	c.now = later
	if _, ok := c.Get(key); ok {
		t.Error("after expiry: got hit, want miss")
	}
	if c.Len() != 0 {
		t.Errorf("len after lazy expiry = %d, want 0", c.Len())
	}
}

func TestMemTemplateWALRoundtrip(t *testing.T) {
	w := NewMemTemplateWAL()
	events := []TemplateEvent{
		{Kind: TemplateAdded, Exporter: "10.0.0.1", ObsDomainID: 1, TemplateID: 1024, Version: VersionNetFlowV9, Body: []byte{1}, TS: time.Unix(1, 0)},
		{Kind: TemplateRemoved, Exporter: "10.0.0.1", ObsDomainID: 1, TemplateID: 1024, TS: time.Unix(2, 0)},
	}
	for _, ev := range events {
		if err := w.Append(ev); err != nil {
			t.Fatalf("append: %v", err)
		}
	}
	got, err := w.Replay()
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if len(got) != len(events) {
		t.Fatalf("replay count = %d, want %d", len(got), len(events))
	}
	for i := range events {
		if got[i].TemplateID != events[i].TemplateID || got[i].Kind != events[i].Kind {
			t.Errorf("event[%d] = %+v, want %+v", i, got[i], events[i])
		}
	}
	if err := w.Close(); err != nil {
		t.Errorf("close: %v", err)
	}
}

func TestKafkaTemplateWALStub(t *testing.T) {
	w := NewKafkaTemplateWAL([]string{"kafka:9092"}, "wal.dat")
	if err := w.Append(TemplateEvent{}); !errors.Is(err, ErrWALNotImplemented) {
		t.Errorf("append err = %v, want ErrWALNotImplemented", err)
	}
	if _, err := w.Replay(); !errors.Is(err, ErrWALNotImplemented) {
		t.Errorf("replay err = %v, want ErrWALNotImplemented", err)
	}
}

func TestStubDecodersNotImplemented(t *testing.T) {
	dg := make([]byte, 32)
	for _, tc := range []struct {
		name string
		d    Decoder
	}{
		{"v9", NewV9(nil, nil)},
		{"ipfix", NewIPFIX(nil, nil)},
		{"sflow", NewSFlow()},
	} {
		if _, err := tc.d.Decode(dg, tplExporter); !errors.Is(err, ErrDecoderNotImplemented) {
			t.Errorf("%s: err = %v, want ErrDecoderNotImplemented", tc.name, err)
		}
	}
}

func TestNewV9DefaultsToMemCacheAndWAL(t *testing.T) {
	d := NewV9(nil, nil)
	if d.cache == nil || d.wal == nil {
		t.Fatal("NewV9(nil,nil) must default to mem cache/wal")
	}
	if d.cache.Len() != 0 {
		t.Errorf("fresh cache len = %d, want 0", d.cache.Len())
	}
}
