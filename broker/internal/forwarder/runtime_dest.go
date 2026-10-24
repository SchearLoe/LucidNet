package forwarder

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/SchearLoe/lucidnet/broker/internal/flowcodec"
	"github.com/SchearLoe/lucidnet/shared"
)

// runtimeDest —— 运行时目的地。配置签名（sig）相同的跨版本复用（会话不中断），
// 任何配置变化生成新实例（= 新 session，旧会话 flush 后关闭，dd/01 §3.2 #5）。
// 断连重放（任务二，dd/01 §4.3）：UDP 目的地持有下行重放缓冲；会话重建
// （sig 变更）视为断连重放场景之一——旧会话缓冲经引擎 stash 移交同逻辑
// 目的地（rule_id|dest 键）的新会话，按序重放。
type runtimeDest interface {
	Sig() string
	// ReplayKey —— 重放缓冲迁移键（rule_id|dest 标签）；"" = 无缓冲（kafka 由 producer 内部缓冲）。
	ReplayKey() string
	// TakeReplay / InstallReplay —— 会话重建时的缓冲迁移。
	TakeReplay() []replayItem
	InstallReplay(items []replayItem, now time.Time)
	Close()
}

// destLabel —— metrics 标签组合（rule_id/dest，docs/11 §9 白名单）。
type destLabel struct{ ruleID, dest string }

// sig —— 目的地配置签名（跨版本复用判定）。
func sig(ruleID int32, idx int, d *Destination) string {
	s := strconv.FormatInt(int64(ruleID), 10) + "|" + strconv.Itoa(idx) + "|" + string(d.Protocol) + "|" + d.Addr
	if d.Resample != nil {
		s += "|" + string(d.Resample.Mode) + "|" + strconv.FormatUint(uint64(d.Resample.Rate), 10)
	}
	return s + "|" + d.Topic
}

// destTag —— dest 标签值（kafka 用 topic 标识，UDP 用 addr）。
func destTag(d *Destination) string {
	if d.Protocol == ProtocolKafka {
		return "kafka:" + d.Topic
	}
	return d.Addr
}

// —— 透传目的地（dd/01 §3.1：零改动复制；再采样不支持已由 Validate 拒绝） ——

type passthroughDest struct {
	sender *udpSender
	sig    string
	key    string // ReplayKey（rule_id|dest）
}

// newPassthroughDest —— 构造透传目的地（不限速：限速属代理会话，dd/01 §4.3）。
func newPassthroughDest(s, replayKey string, d *Destination, counters Counters, lb destLabel, rp replayPolicy) (*passthroughDest, error) {
	var hooks senderHooks
	hooks.onSent = func() { counters.ForwardRecords(lb.ruleID, lb.dest, 1) }
	hooks.onDrop = func() { counters.ForwardDrop(lb.ruleID, lb.dest, 1) }
	dest := lb.dest
	hooks.onDownChange = func(down bool) { counters.SetDestDown(dest, down) }
	hooks.onReplayBuffered = func(n int) { counters.SetReplayBuffered(lb.ruleID, lb.dest, n) }
	hooks.onReplayDropped = func(n int) { counters.ReplayDropped(lb.ruleID, lb.dest, n) }
	hooks.onReplayLag = func(lag time.Duration) { counters.SetReplayLag(lb.ruleID, lb.dest, lag) }
	sender, err := newUDPSender("udp", d.Addr, 0, rp, hooks)
	if err != nil {
		return nil, err
	}
	return &passthroughDest{sender: sender, sig: s, key: replayKey}, nil
}

// Sig 实现 runtimeDest。
func (d *passthroughDest) Sig() string { return d.sig }

// ReplayKey 实现 runtimeDest。
func (d *passthroughDest) ReplayKey() string { return d.key }

// TakeReplay 实现 runtimeDest。
func (d *passthroughDest) TakeReplay() []replayItem { return d.sender.TakeReplay() }

// InstallReplay 实现 runtimeDest。
func (d *passthroughDest) InstallReplay(items []replayItem, now time.Time) {
	d.sender.InstallReplay(items, now)
}

// Close 实现 runtimeDest。
func (d *passthroughDest) Close() { d.sender.Close() }

// deliver —— 复制数据报入队（调用方缓冲会被复用，必须拷贝）。
func (d *passthroughDest) deliver(datagram []byte) {
	buf := make([]byte, len(datagram))
	copy(buf, datagram)
	d.sender.Send(buf)
}

// —— 代理重编码目的地（netflow5/ipfix，dd/01 §4） ——

// proxyFlushInterval —— 会话批 flush 周期（平衡时延与包率）。
const proxyFlushInterval = 200 * time.Millisecond

type proxyDest struct {
	sig    string
	cfg    Destination
	lb     destLabel
	obsDom uint32
	sender *udpSender

	mu    sync.Mutex
	v5    *flowcodec.V5Encoder
	ipfix *flowcodec.IPFIXEncoder

	tick *time.Ticker
	done chan struct{}
}

// newProxyDest 构造代理会话目的地（每目的地独立 session：序列号/模板/限速，dd/01 §4.3）。
func newProxyDest(s string, lb destLabel, obsDom uint32, d *Destination, counters Counters, rp replayPolicy, now time.Time) (*proxyDest, error) {
	var hooks senderHooks
	// 记录数由引擎按 kept records 精确计数（deliverRecords 调用方）；
	// 发送协程钩子只计数据报级丢失（限速/队列溢出/写失败 → drop 打点）。
	hooks.onSent = func() {}
	hooks.onDrop = func() { counters.ForwardDrop(lb.ruleID, lb.dest, 1) }
	dest := lb.dest
	hooks.onDownChange = func(down bool) { counters.SetDestDown(dest, down) }
	hooks.onReplayBuffered = func(n int) { counters.SetReplayBuffered(lb.ruleID, lb.dest, n) }
	hooks.onReplayDropped = func(n int) { counters.ReplayDropped(lb.ruleID, lb.dest, n) }
	hooks.onReplayLag = func(lag time.Duration) { counters.SetReplayLag(lb.ruleID, lb.dest, lag) }
	sender, err := newUDPSender("udp", d.Addr, DefaultProxyRateBytes, rp, hooks)
	if err != nil {
		return nil, err
	}
	pd := &proxyDest{sig: s, cfg: *d, lb: lb, obsDom: obsDom, sender: sender, done: make(chan struct{})}
	switch d.Protocol {
	case ProtocolNetFlow5:
		pd.v5 = flowcodec.NewV5Encoder(now)
	case ProtocolIPFIX:
		pd.ipfix = flowcodec.NewIPFIXEncoder(obsDom, 0)
	}
	if d.Resample != nil && d.Resample.Rate > 1 {
		counters.SetResampleRatio(lb.dest, 1/float64(d.Resample.Rate))
	}
	pd.tick = time.NewTicker(proxyFlushInterval)
	go pd.flushLoop()
	return pd, nil
}

// Sig 实现 runtimeDest。
func (d *proxyDest) Sig() string { return d.sig }

// ReplayKey 实现 runtimeDest。
func (d *proxyDest) ReplayKey() string { return d.lb.ruleID + "|" + d.lb.dest }

// TakeReplay 实现 runtimeDest。
func (d *proxyDest) TakeReplay() []replayItem { return d.sender.TakeReplay() }

// InstallReplay 实现 runtimeDest。
func (d *proxyDest) InstallReplay(items []replayItem, now time.Time) {
	d.sender.InstallReplay(items, now)
}

// deliverRecords —— 过滤/再采样后的记录进入会话编码（调用方已按目的地复制记录）。
func (d *proxyDest) deliverRecords(recs []shared.FlowRecord, counters Counters, now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i := range recs {
		rec := recs[i]
		switch {
		case d.v5 != nil:
			if rec.IPVersion != 4 {
				// v5 表达域仅 IPv4：v6 记录丢弃计数（dd/01 §4.2 限制）
				counters.ForwardDrop(d.lb.ruleID, d.lb.dest, 1)
				continue
			}
			if d.v5.Append(rec) {
				if dg := d.v5.Flush(now); dg != nil {
					d.sender.Send(dg)
				}
			}
		case d.ipfix != nil:
			if d.ipfix.Append(rec) {
				if msg := d.ipfix.Flush(now, d.algo(), d.interval()); msg != nil {
					d.sender.Send(msg)
				}
			}
		}
	}
}

// flushLoop —— 周期 flush（避免长流/低速率下记录滞留缓冲）。
func (d *proxyDest) flushLoop() {
	for {
		select {
		case <-d.done:
			return
		case now := <-d.tick.C:
			d.mu.Lock()
			var dg []byte
			if d.v5 != nil {
				dg = d.v5.Flush(now)
			} else if d.ipfix != nil {
				dg = d.ipfix.Flush(now, d.algo(), d.interval())
			}
			d.mu.Unlock()
			if dg != nil {
				d.sender.Send(dg)
			}
		}
	}
}

// Close 实现 runtimeDest：flush 残留后关闭会话（dd/01 §3.2 #5 平滑切换）。
func (d *proxyDest) Close() {
	close(d.done)
	d.tick.Stop()
	d.mu.Lock()
	now := time.Now()
	if d.v5 != nil {
		if dg := d.v5.Flush(now); dg != nil {
			d.sender.Send(dg)
		}
	} else if d.ipfix != nil {
		if msg := d.ipfix.Flush(now, d.algo(), d.interval()); msg != nil {
			d.sender.Send(msg)
		}
	}
	d.mu.Unlock()
	d.sender.Close()
}

// algo / interval —— 从目的地配置取 IPFIX 采样参数（无 resample 时 1:1 全采）。
func (d *proxyDest) algo() uint8 {
	if d.cfg.Resample == nil || d.cfg.Resample.Rate <= 1 {
		return flowcodec.IPFIXAlgoDeterministic
	}
	if d.cfg.Resample.Mode == ResampleRandom {
		return flowcodec.IPFIXAlgoRandom
	}
	return flowcodec.IPFIXAlgoDeterministic
}

func (d *proxyDest) interval() uint32 {
	if d.cfg.Resample == nil || d.cfg.Resample.Rate <= 1 {
		return 1
	}
	return d.cfg.Resample.Rate
}

// —— Kafka 目的地（产出 flows.raw 等 topic，key 严格按 docs/09 §2/00 §3） ——

type kafkaDest struct {
	sig      string
	topic    string
	lb       destLabel
	kafka    KafkaSink
	counters Counters
	ctx      context.Context //nolint:containedctx // 目的地生命周期内复用后台生产上下文
}

// newKafkaDest 构造 Kafka 目的地（记录级输出，支持独立再采样）。
func newKafkaDest(s string, lb destLabel, d *Destination, kafka KafkaSink, counters Counters) *kafkaDest {
	return &kafkaDest{
		sig:      s,
		topic:    d.Topic,
		lb:       lb,
		kafka:    kafka,
		counters: counters,
		ctx:      context.Background(),
	}
}

// Sig 实现 runtimeDest。
func (d *kafkaDest) Sig() string { return d.sig }

// ReplayKey 实现 runtimeDest（kafka 由 producer 内部缓冲/重试，不参与断连重放）。
func (d *kafkaDest) ReplayKey() string { return "" }

// TakeReplay 实现 runtimeDest（无缓冲，no-op）。
func (d *kafkaDest) TakeReplay() []replayItem { return nil }

// InstallReplay 实现 runtimeDest（no-op）。
func (d *kafkaDest) InstallReplay([]replayItem, time.Time) {}

// Close 实现 runtimeDest（Kafka client 生命周期归引擎，无需逐目的地关闭）。
func (d *kafkaDest) Close() {}

// deliverRecords —— FlowRecord → proto 编码 → Kafka（key=FlowKey(zone_id, exporter)，
// docs/09 §2 + 00 §3；value=FlowRecord proto，lz4 由 producer 配置）。
func (d *kafkaDest) deliverRecords(recs []shared.FlowRecord) {
	for i := range recs {
		rec := &recs[i]
		value := flowcodec.MarshalFlowRecord(rec)
		key := shared.FlowKey(rec.ZoneID, rec.Exporter)
		d.kafka.Produce(d.ctx, d.topic, key, value)
	}
	d.counters.KafkaProduce(d.topic, len(recs))
}
