package forwarder

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/SchearLoe/lucidnet/broker/internal/flowcodec"
	"github.com/SchearLoe/lucidnet/shared"
)

// Engine —— R1 转发规则引擎（dd/01 §3）：规则命中 → 多目的转发。
// 未配置规则时零额外开销（空表 O(1) 判断，dd/01 §1）。
type Engine struct {
	snapshot SnapshotPtr

	kafka    KafkaSink
	counters Counters
	now      func() time.Time // 可注入时钟（测试）

	mu    sync.RWMutex
	dests map[string]runtimeDest // sig → 运行时目的地（跨版本复用）
}

// NewEngine 构造（kafka 可为 nil：仅当规则含 kafka 目的地时必需）。
func NewEngine(kafka KafkaSink, counters Counters) *Engine {
	if counters == nil {
		counters = NoopCounters{}
	}
	return &Engine{
		kafka:    kafka,
		counters: counters,
		now:      time.Now,
		dests:    map[string]runtimeDest{},
	}
}

// SetClock 注入时钟（测试）。
func (e *Engine) SetClock(now func() time.Time) { e.now = now }

// Process —— 收包路径入口（复制点在 FLB 之前，dd/01 §1）。
// datagram 缓冲归调用方所有，本方法不滞留引用。
func (e *Engine) Process(datagram []byte, src netip.Addr) {
	set := e.snapshot.Load()
	rules := set.RulesFor(src.String())
	if len(rules) == 0 {
		return // 空表 O(1)：未配置规则零额外开销
	}

	var decoded []shared.FlowRecord // 懒解码：同报文多目的地复用一次解码
	decodeFailed := false
	for _, cr := range rules {
		for _, d := range cr.dests {
			rd := e.destFor(cr, d)
			if rd == nil {
				continue
			}
			switch pd := rd.(type) {
			case *passthroughDest:
				pd.deliver(datagram)
			case *proxyDest:
				if decodeFailed {
					continue
				}
				if decoded == nil {
					var err error
					decoded, err = e.decode(datagram, src)
					if err != nil {
						decodeFailed = true
						e.counters.ProxyDecodeError()
						continue
					}
				}
				kept := e.filterAndResample(cr.filter, d, decoded)
				pd.deliverRecords(kept, e.counters, e.now())
				e.counters.ForwardRecords(strconv.FormatInt(int64(cr.src.ID), 10), labelOf(d), len(kept))
			case *kafkaDest:
				if decodeFailed {
					continue
				}
				if decoded == nil {
					var err error
					decoded, err = e.decode(datagram, src)
					if err != nil {
						decodeFailed = true
						e.counters.ProxyDecodeError()
						continue
					}
				}
				kept := e.filterAndResample(cr.filter, d, decoded)
				pd.deliverRecords(kept)
			}
		}
	}
}

// labelOf —— 目的地标签（与 runtimeDest 构造保持一致）。
func labelOf(d *Destination) string { return destTag(d) }

// decode —— 代理路径报文解码（MVP：NetFlow v5 完整实现；v9/IPFIX/sFlow 随
// GoFlow2 fork 接入扩展，dd/01 §4 与 collector 同步演进）。
func (e *Engine) decode(datagram []byte, src netip.Addr) ([]shared.FlowRecord, error) {
	switch flowcodec.PeekVersion(datagram) {
	case 5:
		recs, _, err := flowcodec.DecodeV5(datagram, src)
		return recs, err
	default:
		return nil, errors.New("forwarder: proxy decode not supported for this protocol (v9/ipfix/sflow pending goflow2 fork, dd/01 §4)")
	}
}

// filterAndResample —— 内容过滤 + 再采样（dd/01 §3.2 #4、§4.1），
// 返回按目的地独立的记录副本（effective_sample_rate 写回 sample_rate）。
func (e *Engine) filterAndResample(f *Filter, d *Destination, recs []shared.FlowRecord) []shared.FlowRecord {
	sampler := NewSampler(d.Resample)
	kept := make([]shared.FlowRecord, 0, len(recs))
	for i := range recs {
		rec := &recs[i]
		if !f.Match(rec) {
			continue
		}
		if !sampler.Keep(rec) {
			continue
		}
		out := *rec
		if d.Resample != nil && d.Resample.Rate > 1 {
			out.SampleRate = EffectiveSampleRate(rec.SampleRate, d.Resample.Rate)
		}
		kept = append(kept, out)
	}
	return kept
}

// destFor —— 查找/创建运行时目的地（RWMutex 双检；创建失败返回 nil 并丢弃）。
func (e *Engine) destFor(cr *compiledRule, d *Destination) runtimeDest {
	key := sig(cr.src.ID, destIndex(cr, d), d)
	e.mu.RLock()
	rd, ok := e.dests[key]
	e.mu.RUnlock()
	if ok {
		return rd
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if rd, ok = e.dests[key]; ok {
		return rd
	}
	rd, err := e.buildDest(cr, d, key)
	if err != nil {
		e.counters.ForwardDrop(strconv.FormatInt(int64(cr.src.ID), 10), destTag(d), 1)
		return nil
	}
	e.dests[key] = rd
	return rd
}

// destIndex —— 目的地在规则内的下标（sig 复用与 obsDomain 计算用）。
func destIndex(cr *compiledRule, d *Destination) int {
	for i := range cr.dests {
		if cr.dests[i] == d {
			return i
		}
	}
	return -1
}

// buildDest —— 按协议构造运行时目的地。
func (e *Engine) buildDest(cr *compiledRule, d *Destination, key string) (runtimeDest, error) {
	lb := destLabel{ruleID: strconv.FormatInt(int64(cr.src.ID), 10), dest: destTag(d)}
	obsDom := uint32(cr.src.ID)*1000 + uint32(destIndex(cr, d)+1) // Observation Domain = 规则目的地 id（dd/01 §4.2）
	switch d.Protocol {
	case ProtocolPassthrough:
		var hooks senderHooks
		hooks.onSent = func() { e.counters.ForwardRecords(lb.ruleID, lb.dest, 1) }
		hooks.onDrop = func() { e.counters.ForwardDrop(lb.ruleID, lb.dest, 1) }
		dest := lb.dest
		hooks.onDownChange = func(down bool) { e.counters.SetDestDown(dest, down) }
		sender, err := newUDPSender("udp", d.Addr, 0, hooks) // 透传不限速（限速属代理会话，dd/01 §4.3）
		if err != nil {
			return nil, fmt.Errorf("forwarder: dial passthrough dest %s: %w", d.Addr, err)
		}
		return &passthroughDest{sender: sender, sig: key}, nil
	case ProtocolNetFlow5, ProtocolIPFIX:
		return newProxyDest(key, lb, obsDom, d, e.counters, e.now())
	case ProtocolKafka:
		if e.kafka == nil {
			return nil, errors.New("forwarder: kafka destination but no kafka producer configured")
		}
		return newKafkaDest(key, lb, d, e.kafka, e.counters), nil
	default:
		return nil, fmt.Errorf("forwarder: unknown protocol %q", d.Protocol)
	}
}

// ApplyRules —— 版本化热更新（admin watch 回调；dd/01 §3.2 #5）：
// 编译快照 → 重建/复用运行时目的地 → 原子换表 → 旧会话 flush 后关闭。
func (e *Engine) ApplyRules(snap *RulesSnapshot) (*RuleSet, []error) {
	rs, verrs := Compile(snap)

	e.mu.Lock()
	keep := make(map[string]struct{}, len(rs.byExporter)*2)
	var stale []runtimeDest
	// 收集新表引用的全部 sig
	for i := range rs.rules {
		cr := &rs.rules[i]
		for _, d := range cr.dests {
			keep[sig(cr.src.ID, destIndex(cr, d), d)] = struct{}{}
		}
	}
	for k, rd := range e.dests {
		if _, used := keep[k]; !used {
			stale = append(stale, rd)
			delete(e.dests, k)
		}
	}
	e.mu.Unlock()

	e.snapshot.Store(rs) // 原子换表：新流量即刻走新目的地
	for _, rd := range stale {
		rd.Close() // 旧会话 flush 后关闭（缓冲残留仍在队列中送达）
	}
	return rs, verrs
}

// RulesSnapshotPtr —— 供自监控读取当前版本。
func (e *Engine) Rules() *RuleSet { return e.snapshot.Load() }

// Close —— 关停全部目的地（进程退出路径）。
func (e *Engine) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for k, rd := range e.dests {
		rd.Close()
		delete(e.dests, k)
	}
}
