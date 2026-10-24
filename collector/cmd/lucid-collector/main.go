// lucid-collector —— 采集解析组件入口（hld/02：UDP 解码 → 归一化 FlowRecord →
// 富化 → Kafka；SNMP 采集与接口角色识别）。
//
// Walking skeleton 组装：v5 解码真实实现；v9/IPFIX/sFlow/真实 Kafka/gosnmp 为桩
// （TODO 对应 dd/02 章节）；配置入口 = flags（生产为 etcd watch，dd/02 §6）。
package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/SchearLoe/lucidnet/collector/internal/decoder"
	"github.com/SchearLoe/lucidnet/collector/internal/enrich"
	"github.com/SchearLoe/lucidnet/collector/internal/etcdcfg"
	"github.com/SchearLoe/lucidnet/collector/internal/nodecfg"
	"github.com/SchearLoe/lucidnet/collector/internal/producer"
	"github.com/SchearLoe/lucidnet/collector/internal/snmp"
	"github.com/SchearLoe/lucidnet/collector/internal/zone"
	"github.com/SchearLoe/lucidnet/shared"
)

// flags —— 骨架本地配置（dd/02 §6：生产配置全量 etcd，本地仅 bind 地址；
// 环境变量约定 LUCID_COLLECTOR_* 见 docs/11 §8）。
type flags struct {
	listen         string // NetFlow v5/v9/IPFIX UDP（hld/02 §4：2055/9995/9996）
	sflowListen    string // sFlow UDP（版本字段与 NetFlow v5 冲突，按端口分流；空=禁用）
	node           string // 节点 ID（/lucid/config/collector/{node} 键尾；缺省主机名）
	zonesFile      string // /lucid/zones 值快照（信封 JSON；etcd watch 开发替身）
	nodeConfigFile string // /lucid/config/collector/{node} 值快照（信封 JSON；开发替身）
	zoneMatch      string // dst|src（docs/09 §3，默认 dst，禁止 both；node 配置可覆盖）
	out            string // console | file | kafka（kafka=franz-go 桩）
	outFile        string
	kafkaBrokers   string
	ribFile        string // RIB 快照文件（开发：RibNameLookup gRPC 替身）
	runSNMP        bool   // 启动 SNMP 调度器（gosnmp 桩，无设备即空转）
}

func parseFlags() flags {
	var f flags
	flag.StringVar(&f.listen, "listen", ":2055", "NetFlow v5/v9/IPFIX UDP 监听地址（可被 node 配置覆盖）")
	flag.StringVar(&f.sflowListen, "sflow-listen", "", "sFlow UDP 监听地址（默认禁用；生产 :6343，hld/02 §4；可被 node 配置覆盖）")
	flag.StringVar(&f.node, "node", defaultNode(), "节点 ID（/lucid/config/collector/{node} 键尾；缺省主机名）")
	flag.StringVar(&f.zonesFile, "zones-file", "", "/lucid/zones 值快照（信封 JSON，etcd watch 开发替身）")
	flag.StringVar(&f.nodeConfigFile, "node-config-file", "", "/lucid/config/collector/{node} 值快照（信封 JSON，开发替身）")
	flag.StringVar(&f.zoneMatch, "zone-match", "dst", "zone 匹配面：dst | src（docs/09 §3，禁止 both；node 配置可覆盖）")
	flag.StringVar(&f.out, "out", "console", "输出模式：console | file | kafka（kafka 为 franz-go 桩）")
	flag.StringVar(&f.outFile, "out-file", "flows.jsonl", "out=file 时的输出文件（JSON 行追加）")
	flag.StringVar(&f.kafkaBrokers, "kafka-brokers", "", "out=kafka 时的 broker 列表（逗号分隔）")
	flag.StringVar(&f.ribFile, "rib-file", "", "RIB 快照 JSON（RibNameLookup 开发替身；空=gRPC 桩）")
	flag.BoolVar(&f.runSNMP, "snmp", false, "启动 SNMP 轮询调度器（gosnmp 桩）")
	flag.Parse()
	return f
}

// defaultNode —— 节点 ID 缺省：主机名（注册键与 Master 登记一致；取不到退 local）。
func defaultNode() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "local"
	}
	return h
}

// counters —— 骨架自监控计数（生产 = Prometheus lucid_collector_*，docs/11 §9）。
type counters struct {
	datagrams     atomic.Uint64
	decoded       atomic.Uint64
	records       atomic.Uint64
	produced      atomic.Uint64
	decodeErrors  atomic.Uint64
	produceErrors atomic.Uint64
	unknownVer    atomic.Uint64
	readErrors    atomic.Uint64
}

// logJSON —— JSON 单行日志（docs/11 §9 固定字段；结构化 logger 接入前的骨架实现）。
func logJSON(msg string, fields map[string]any) {
	if fields == nil {
		fields = make(map[string]any, 2)
	}
	fields["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
	fields["module"] = "collector"
	fields["msg"] = msg
	b, err := json.Marshal(fields)
	if err != nil {
		log.Printf("ts=%s module=collector msg=%q marshal_error=%q", fields["ts"], msg, err)
		return
	}
	log.Println(string(b))
}

func main() {
	if err := run(parseFlags()); err != nil {
		logJSON("exit", map[string]any{"err": err.Error()})
		os.Exit(1)
	}
}

func run(f flags) error {
	// 优雅退出：SIGINT/SIGTERM → ctx 取消（systemd 部署，dd/02 §6）。
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runCollector(ctx, f)
}

// runCollector —— 组装并运行至 ctx 取消（main 与 e2e 测试共用）。
func runCollector(ctx context.Context, f flags) error {
	// —— 配置入口（etcd 值信封，09 §5 2026-10-25 裁定；文件快照为 watch 开发替身）——
	// 所有信封键共用版本守卫：乱序回放（≤已应用版本）忽略并日志打点。
	guard := etcdcfg.NewGuard()

	// —— Zone 匹配器（R2 关键路径）——
	matchField, err := zone.ParseMatchField(f.zoneMatch)
	if err != nil {
		return fmt.Errorf("zone-match: %w", err)
	}
	matcher := zone.NewMatcher(matchField)
	if f.zonesFile != "" {
		data, err := os.ReadFile(f.zonesFile)
		if err != nil {
			return fmt.Errorf("read zones file %s: %w", f.zonesFile, err)
		}
		if err := applyZonesSnapshot(matcher, guard, data); err != nil {
			return fmt.Errorf("zones file %s: %w", f.zonesFile, err)
		}
	}

	// —— per-node 配置（/lucid/config/collector/{node}；09 §5：端口/采样登记表/
	// 命名正则/RIB 快照指针；zone_match 与监听地址即时生效，其余字段 TODO 接线）——
	var nodeCfg nodecfg.Config
	if f.nodeConfigFile != "" {
		data, err := os.ReadFile(f.nodeConfigFile)
		if err != nil {
			return fmt.Errorf("read node config %s: %w", f.nodeConfigFile, err)
		}
		nodeCfg, err = applyNodeConfig(matcher, guard, f.node, data)
		if err != nil {
			return fmt.Errorf("node config %s: %w", f.nodeConfigFile, err)
		}
	}
	listen, sflowListen := f.listen, f.sflowListen
	if nodeCfg.Listen != "" {
		listen = nodeCfg.Listen
		logJSON("node config overrides listen", map[string]any{"listen": listen})
	}
	if nodeCfg.SFlowListen != "" {
		sflowListen = nodeCfg.SFlowListen
		logJSON("node config overrides sflow listen", map[string]any{"sflow_listen": sflowListen})
	}

	// —— RIB（ASN/前缀富化源，dd/02 §3.1）——
	var rib enrich.RibLookup
	if f.ribFile != "" {
		snap, err := enrich.LoadRibSnapshot(f.ribFile)
		if err != nil {
			return err
		}
		rib = snap
		logJSON("rib snapshot loaded", map[string]any{"file": f.ribFile, "entries": snap.Len()})
	} else {
		rib = enrich.NewGRPCRIB(shared.AddrRibNameLookup) // gRPC 桩（Lookup 恒 miss）
	}

	// —— 富化流水线（ASN→Geo→App→Zone→IfRole，dd/02 §3）——
	// Geo/App/IfRole 为桩/空表（mmdb、PG 静态表、interfaces 快照接入 TODO，dd/02 §3.2/§3.4）。
	pipe := enrich.NewPipeline(rib, enrich.NewGeoStub(), enrich.NewAppTable(), matcher, enrich.NewIfRoleSnapshot())

	// —— 输出（Kafka 契约 key=FlowKey(zone_id, exporter)，dd/02 §4）——
	out, err := newProducer(f)
	if err != nil {
		return err
	}
	defer out.Close()

	st := &counters{}
	dispatch := newDispatcher(pipe, out, st)

	// —— UDP 监听（TODO(reuseport)：生产多 socket 并行解码，dd/02 §1）——
	var wg sync.WaitGroup
	conns := make([]*net.UDPConn, 0, 2)
	netflowConn, err := listenUDP(listen)
	if err != nil {
		return err
	}
	conns = append(conns, netflowConn)
	wg.Add(1)
	go serveUDP(ctx, &wg, netflowConn, dispatch.handleNetFlow, st)
	logJSON("listening", map[string]any{"addr": listen, "proto": "netflow"})

	if sflowListen != "" {
		sflowConn, err := listenUDP(sflowListen)
		if err != nil {
			netflowConn.Close()
			return err
		}
		conns = append(conns, sflowConn)
		wg.Add(1)
		go serveUDP(ctx, &wg, sflowConn, dispatch.handleSFlow, st)
		logJSON("listening", map[string]any{"addr": sflowListen, "proto": "sflow"})
	}

	// —— SNMP 调度器（gosnmp 桩；设备清单来自 PG devices，TODO(dd/02 §5.1)）——
	var snmpWG sync.WaitGroup
	if f.runSNMP {
		sched := snmp.NewScheduler(snmp.NewGoSNMPPoller())
		snmpWG.Add(1)
		go func() {
			defer snmpWG.Done()
			sched.Run(ctx) // 无设备时空转，仅演示组装位
		}()
		logJSON("snmp scheduler started", map[string]any{"poller": "gosnmp-stub"})
	}

	// —— 周期自监控（生产 = Prometheus /metrics，dd/02 §6）——
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				logJSON("stats", st.snapshot())
			}
		}
	}()

	<-ctx.Done()
	logJSON("shutting down", nil)

	// 关 socket 解除 Read 阻塞 → 等处理协程落地 → 冲刷输出。
	for _, c := range conns {
		c.Close()
	}
	wg.Wait()
	snmpWG.Wait()

	flushCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := out.Flush(flushCtx); err != nil {
		logJSON("flush error", map[string]any{"err": err.Error()})
	}
	logJSON("stopped", st.snapshot())
	return nil
}

// applyZonesSnapshot —— /lucid/zones 值（信封，09 §5）：
// 解信封 → 版本守卫 → 裸 payload 解析 → 原子换树（COW）。
// 生产 watch 路径（etcd watch → 本函数）与文件替身共用此入口；
// 裸 payload（无信封）在此报错，payload 解析全部发生在信封解包之后。
func applyZonesSnapshot(m *zone.Matcher, g *etcdcfg.Guard, data []byte) error {
	env, err := etcdcfg.Decode(data)
	if err != nil {
		return fmt.Errorf("decode %s envelope: %w", shared.EtcdKeyZones, err)
	}
	if !g.ShouldApply(shared.EtcdKeyZones, env.Version) {
		logJSON("config stale ignored", map[string]any{
			"key": shared.EtcdKeyZones, "version": env.Version,
			"applied_version": g.Applied(shared.EtcdKeyZones),
		})
		return nil
	}
	specs, err := zone.ParseSpecsJSON(env.Data)
	if err != nil {
		return fmt.Errorf("parse %s payload v%d: %w", shared.EtcdKeyZones, env.Version, err)
	}
	if err := m.Update(specs); err != nil {
		return fmt.Errorf("apply %s v%d: %w", shared.EtcdKeyZones, env.Version, err)
	}
	g.MarkApplied(shared.EtcdKeyZones, env.Version)
	logJSON("config applied", map[string]any{
		"key": shared.EtcdKeyZones, "version": env.Version,
		"updated_at": env.UpdatedAt.Format(time.RFC3339), "zones": len(specs),
	})
	return nil
}

// applyNodeConfig —— /lucid/config/collector/{node} 值（信封，09 §5）：
// 解信封 → 版本守卫 → 负载解析 → 应用。返回负载供调用方接线（监听地址等）。
//
// 即时生效：zone_match（热切，覆盖本地 flag 缺省，dd/02 §6 配置全量 etcd）。
// TODO 接线（nodecfg.Config 注释）：采样登记表 → v5 per-exporter 采样；
// 命名正则表 → snmp.RuleEngine；RIB 快照指针 → RIB Feeder 拉取；
// 监听地址变更热重载（需重建 socket）。
func applyNodeConfig(m *zone.Matcher, g *etcdcfg.Guard, node string, data []byte) (nodecfg.Config, error) {
	key := shared.EtcdKeyConfigCollector + node
	env, err := etcdcfg.Decode(data)
	if err != nil {
		return nodecfg.Config{}, fmt.Errorf("decode %s envelope: %w", key, err)
	}
	if !g.ShouldApply(key, env.Version) {
		logJSON("config stale ignored", map[string]any{
			"key": key, "version": env.Version, "applied_version": g.Applied(key),
		})
		return nodecfg.Config{}, nil
	}
	cfg, err := nodecfg.Parse(env.Data)
	if err != nil {
		return nodecfg.Config{}, fmt.Errorf("parse %s payload v%d: %w", key, env.Version, err)
	}
	if cfg.ZoneMatch != "" {
		mf, err := zone.ParseMatchField(cfg.ZoneMatch)
		if err != nil {
			return nodecfg.Config{}, fmt.Errorf("apply %s v%d zone_match: %w", key, env.Version, err)
		}
		m.SetMatchField(mf)
	}
	g.MarkApplied(key, env.Version)
	logJSON("config applied", map[string]any{
		"key": key, "version": env.Version,
		"updated_at":              env.UpdatedAt.Format(time.RFC3339),
		"zone_match":              m.MatchField().String(),
		"sample_registry_entries": len(cfg.SampleRegistry),
		"naming_rules":            len(cfg.NamingRules),
		"rib_snapshot_ptr":        cfg.RIBSnapshotPtr,
	})
	return cfg, nil
}

// newProducer —— 按 -out 构造输出。
func newProducer(f flags) (producer.FlowProducer, error) {
	switch f.out {
	case "console":
		return producer.NewConsole(bufio.NewWriter(os.Stdout)), nil
	case "file":
		return producer.NewFile(f.outFile)
	case "kafka":
		brokers := splitCSV(f.kafkaBrokers)
		if len(brokers) == 0 {
			return nil, errors.New("out=kafka requires -kafka-brokers")
		}
		return producer.NewKafka(producer.DefaultKafkaConfig(brokers))
	default:
		return nil, fmt.Errorf("unknown -out %q (want console|file|kafka)", f.out)
	}
}

// splitCSV —— 逗号分隔列表（空段丢弃）。
func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// dispatcher —— 数据报版本分流 → 解码 → 富化 → 生产。
type dispatcher struct {
	v5    *decoder.V5Decoder
	v9    decoder.Decoder // goflow2 fork 桩（dd/02 §1）
	ipfix decoder.Decoder // goflow2 fork 桩（dd/02 §1）
	sflow decoder.Decoder // goflow2 fork 桩（dd/02 §1）
	pipe  *enrich.Pipeline
	out   producer.FlowProducer
	st    *counters
}

func newDispatcher(pipe *enrich.Pipeline, out producer.FlowProducer, st *counters) *dispatcher {
	return &dispatcher{
		v5:    decoder.NewV5(),
		v9:    decoder.NewV9(nil, nil),
		ipfix: decoder.NewIPFIX(nil, nil),
		sflow: decoder.NewSFlow(),
		pipe:  pipe, out: out, st: st,
	}
}

// handleNetFlow —— NetFlow 家族按头部 version 分流（v5 首 2B 与 sFlow v5 首 4B
// 数值冲突，靠端口隔离，见 decoder 包注释）。
func (d *dispatcher) handleNetFlow(datagram []byte, exporter netip.Addr) {
	d.st.datagrams.Add(1)
	if len(datagram) < 2 {
		d.st.unknownVer.Add(1)
		return
	}
	var dec decoder.Decoder
	switch binary.BigEndian.Uint16(datagram[0:2]) {
	case decoder.VersionNetFlowV5:
		dec = d.v5
	case decoder.VersionNetFlowV9:
		dec = d.v9
	case decoder.VersionIPFIX:
		dec = d.ipfix
	default:
		d.st.unknownVer.Add(1)
		return
	}
	d.decodeEnrichProduce(datagram, exporter, dec)
}

// handleSFlow —— sFlow 端口（桩）。
func (d *dispatcher) handleSFlow(datagram []byte, exporter netip.Addr) {
	d.st.datagrams.Add(1)
	d.decodeEnrichProduce(datagram, exporter, d.sflow)
}

func (d *dispatcher) decodeEnrichProduce(datagram []byte, exporter netip.Addr, dec decoder.Decoder) {
	res, err := dec.Decode(datagram, exporter)
	if err != nil {
		d.st.decodeErrors.Add(1)
		return
	}
	d.st.decoded.Add(1)
	for i := range res.Records {
		rec := &res.Records[i]
		d.pipe.Enrich(rec) // ASN→Geo→App→Zone→IfRole（dd/02 §3）
		d.st.records.Add(1)
		if err := d.out.Produce(context.Background(), rec); err != nil {
			d.st.produceErrors.Add(1)
		} else {
			d.st.produced.Add(1)
		}
	}
}

// listenUDP —— 监听（支持 ":2055" / "127.0.0.1:2055"）。
func listenUDP(addr string) (*net.UDPConn, error) {
	a, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve udp addr %s: %w", addr, err)
	}
	conn, err := net.ListenUDP("udp", a)
	if err != nil {
		return nil, fmt.Errorf("listen udp %s: %w", addr, err)
	}
	return conn, nil
}

// serveUDP —— 单 socket 读循环（骨架：单协程串行处理；生产 SO_REUSEPORT 多路并行）。
func serveUDP(ctx context.Context, wg *sync.WaitGroup, conn *net.UDPConn, handler func([]byte, netip.Addr), st *counters) {
	defer wg.Done()
	buf := make([]byte, 65535)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			st.readErrors.Add(1)
			continue
		}
		if addr == nil {
			continue
		}
		handler(buf[:n], addr.AddrPort().Addr())
	}
}

// snapshot —— 计数快照（日志字段 snake_case，docs/11 §9）。
func (c *counters) snapshot() map[string]any {
	return map[string]any{
		"datagrams":      c.datagrams.Load(),
		"decoded":        c.decoded.Load(),
		"records":        c.records.Load(),
		"produced":       c.produced.Load(),
		"decode_errors":  c.decodeErrors.Load(),
		"produce_errors": c.produceErrors.Load(),
		"unknown_ver":    c.unknownVer.Load(),
		"read_errors":    c.readErrors.Load(),
	}
}
