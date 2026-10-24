package flowcodec

import (
	"encoding/binary"
	"time"

	"github.com/SchearLoe/lucidnet/shared"
)

// IPFIX（RFC 7011）重编码（dd/01 §4.2）：自有 Template + Data Set；
// Observation Domain ID = 规则目的地 id；Template ID 每会话 256 起；
// 采样率写标准 IE samplingPacketInterval(305) / samplingPacketAlgorithm(304)（Options Template）。

// IANA IPFIX enterprise-free 信息元素编号（RFC 7011/5102/7102）。
const (
	ieOctetDeltaCount          = 1   // uint64
	iePacketDeltaCount         = 2   // uint64
	ieIPClassOfService         = 5   // uint8
	ieProtocolIdentifier       = 4   // uint8
	ieSourceTransportPort      = 7   // uint16
	ieSourceIPv4Address        = 8   // 4B
	ieIngressInterface         = 10  // uint32
	ieDestinationTransportPort = 11  // uint16
	ieDestinationIPv4Address   = 12  // 4B
	ieEgressInterface          = 14  // uint32
	ieBGPSourceASNumber        = 16  // uint32
	ieBGPDestinationASNumber   = 17  // uint32
	ieSourceIPv6Address        = 27  // 16B
	ieDestinationIPv6Address   = 28  // 16B
	ieFlowStartMilliseconds    = 152 // dateTimeMilliseconds
	ieFlowEndMilliseconds      = 153 // dateTimeMilliseconds
	ieUnionTCPFlags            = 232 // uint8
	ieSamplingPacketAlgorithm  = 304 // uint8
	ieSamplingPacketInterval   = 305 // uint32
)

// 采样算法枚举（IANA，经 samplingPacketAlgorithm 下发）。
const (
	IPFIXAlgoDeterministic uint8 = 1
	IPFIXAlgoRandom        uint8 = 2
)

const (
	ipfixVersion       = 10
	ipfixHeaderLen     = 16
	ipfixTemplateSetID = 2
	ipfixOptionsSetID  = 3

	// 每会话模板 ID 基线（dd/01 §4.2：Template ID=256 起每会话独立）。
	ipfixDataTemplateV4   = 256
	ipfixDataTemplateV6   = 257
	ipfixSamplingTemplate = 258

	// 单消息记录上限：v4 记录 56B/v6 记录 80B，25 条 ≈ 2KB，留足 UDP 载荷余量。
	ipfixMaxRecordsPerMessage = 25
)

// IPFIXEncoder —— 单目的地 IPFIX 会话编码器（非并发安全，由目的地串行驱动）。
type IPFIXEncoder struct {
	obsDomain uint32

	sequence      uint32 // 数据记录计数（RFC 7011 §3.1.1，模 2^32）
	templateDone  bool
	lastTemplate  time.Time
	templateEvery time.Duration

	pending []shared.FlowRecord
}

// NewIPFIXEncoder 构造会话（obsDomain=规则目的地 id；templateEvery 模板重发周期，≤0 取 600s）。
func NewIPFIXEncoder(obsDomain uint32, templateEvery time.Duration) *IPFIXEncoder {
	if templateEvery <= 0 {
		templateEvery = 600 * time.Second
	}
	return &IPFIXEncoder{obsDomain: obsDomain, templateEvery: templateEvery}
}

// Pending 返回缓冲记录数。
func (e *IPFIXEncoder) Pending() int { return len(e.pending) }

// Append 缓冲一条记录；达到单消息上限返回 true 提示 Flush。
func (e *IPFIXEncoder) Append(rec shared.FlowRecord) bool {
	e.pending = append(e.pending, rec)
	return len(e.pending) >= ipfixMaxRecordsPerMessage
}

// Flush 产出一个 IPFIX Message（含到期模板集 + 数据集）；无数据且模板未到期返回 nil。
func (e *IPFIXEncoder) Flush(now time.Time, algo uint8, interval uint32) []byte {
	templateDue := !e.templateDone || now.Sub(e.lastTemplate) >= e.templateEvery
	if len(e.pending) == 0 && !templateDue {
		return nil
	}

	var msg []byte
	if templateDue {
		msg = appendIPFIXSet(msg, e.templateSets(algo, interval, now))
		e.templateDone = true
		e.lastTemplate = now
	}
	if len(e.pending) > 0 {
		v4, v6 := e.dataSets()
		if v4 != nil {
			msg = appendIPFIXSet(msg, v4)
		}
		if v6 != nil {
			msg = appendIPFIXSet(msg, v6)
		}
		e.sequence += uint32(len(e.pending))
		e.pending = e.pending[:0]
	}
	if len(msg) == 0 {
		return nil
	}

	// 消息头（RFC 7011 §3.1）。
	head := make([]byte, ipfixHeaderLen)
	binary.BigEndian.PutUint16(head[0:2], ipfixVersion)
	binary.BigEndian.PutUint16(head[2:4], uint16(ipfixHeaderLen+len(msg)))
	binary.BigEndian.PutUint32(head[4:8], uint32(now.Unix()))
	binary.BigEndian.PutUint32(head[8:12], e.sequence)
	binary.BigEndian.PutUint32(head[12:16], e.obsDomain)
	return append(head, msg...)
}

// templateSets —— 数据模板（v4/v6）+ 采样 Options 模板（305/304，dd/01 §4.2）。
func (e *IPFIXEncoder) templateSets(algo uint8, interval uint32, now time.Time) []byte {
	// —— v4 数据模板：15 字段
	fields4 := []templateField{
		{ieFlowStartMilliseconds, 8}, {ieFlowEndMilliseconds, 8},
		{ieSourceIPv4Address, 4}, {ieDestinationIPv4Address, 4},
		{ieSourceTransportPort, 2}, {ieDestinationTransportPort, 2},
		{ieProtocolIdentifier, 1},
		{iePacketDeltaCount, 8}, {ieOctetDeltaCount, 8},
		{ieUnionTCPFlags, 1}, {ieIPClassOfService, 1},
		{ieIngressInterface, 4}, {ieEgressInterface, 4},
		{ieBGPSourceASNumber, 4}, {ieBGPDestinationASNumber, 4},
	}
	t4 := encodeTemplateSet(ipfixTemplateSetID, ipfixDataTemplateV4, fields4)

	// —— v6 数据模板：同构，地址换 16B
	fields6 := append([]templateField{}, fields4...)
	fields6[2] = templateField{ieSourceIPv6Address, 16}
	fields6[3] = templateField{ieDestinationIPv6Address, 16}
	t6 := encodeTemplateSet(ipfixTemplateSetID, ipfixDataTemplateV6, fields6)

	// —— 采样 Options 模板：scope=System(0,4B)，字段 samplingPacketInterval/Algorithm
	opt := encodeOptionsSet(ipfixSamplingTemplate,
		templateField{0, 4},
		[]templateField{{ieSamplingPacketInterval, 4}, {ieSamplingPacketAlgorithm, 1}},
		[][]byte{samplingOptionsRecord(algo, interval)})
	return append(append(t4, t6...), opt...)
}

// dataSets —— 按 ip_version 拆两个数据集（模板定长 → v4/v6 必须分集）。
func (e *IPFIXEncoder) dataSets() (v4Set, v6Set []byte) {
	var v4Recs, v6Recs [][]byte
	for i := range e.pending {
		rec := &e.pending[i]
		if rec.IPVersion == 6 {
			v6Recs = append(v6Recs, e.encodeDataRecord(rec, true))
		} else {
			v4Recs = append(v4Recs, e.encodeDataRecord(rec, false))
		}
	}
	if len(v4Recs) > 0 {
		v4Set = encodeDataSet(ipfixDataTemplateV4, v4Recs)
	}
	if len(v6Recs) > 0 {
		v6Set = encodeDataSet(ipfixDataTemplateV6, v6Recs)
	}
	return v4Set, v6Set
}

// encodeDataRecord —— 与 templateSets 字段序严格一致。
func (e *IPFIXEncoder) encodeDataRecord(rec *shared.FlowRecord, v6 bool) []byte {
	b := make([]byte, 0, 80)
	b = binary.BigEndian.AppendUint64(b, uint64(rec.TimeStartMs)) // flowStartMilliseconds
	b = binary.BigEndian.AppendUint64(b, uint64(rec.TimeEndMs))   // flowEndMilliseconds
	if v6 {
		b = append(b, rec.SrcIP[:]...)
		b = append(b, rec.DstIP[:]...)
	} else {
		b = append(b, rec.SrcIP[12:16]...)
		b = append(b, rec.DstIP[12:16]...)
	}
	b = binary.BigEndian.AppendUint16(b, uint16(rec.SrcPort))
	b = binary.BigEndian.AppendUint16(b, uint16(rec.DstPort))
	b = append(b, uint8(rec.Proto))
	b = binary.BigEndian.AppendUint64(b, rec.Packets)
	b = binary.BigEndian.AppendUint64(b, rec.Bytes)
	b = append(b, uint8(rec.TCPFlags))
	b = append(b, uint8(rec.TOS))
	b = binary.BigEndian.AppendUint32(b, rec.InIf)
	b = binary.BigEndian.AppendUint32(b, rec.OutIf)
	b = binary.BigEndian.AppendUint32(b, rec.SrcAS)
	b = binary.BigEndian.AppendUint32(b, rec.DstAS)
	return b
}

// templateField —— 数据模板字段说明符。
type templateField struct{ ie, length uint16 }

func encodeTemplateSet(setID, templateID uint16, fields []templateField) []byte {
	set := make([]byte, 0, 8+len(fields)*4)
	setLen := 8 + 4*len(fields) // 头 8B（setID+length+templateID+fieldCount）+ 每字段 4B
	set = binary.BigEndian.AppendUint16(set, setID)
	set = binary.BigEndian.AppendUint16(set, uint16(setLen))
	set = binary.BigEndian.AppendUint16(set, templateID)
	set = binary.BigEndian.AppendUint16(set, uint16(len(fields)))
	for _, f := range fields {
		set = binary.BigEndian.AppendUint16(set, f.ie)
		set = binary.BigEndian.AppendUint16(set, f.length)
	}
	return set
}

// encodeOptionsSet —— Options Template Set + 预编码 options 记录（RFC 7011 §3.4.2）。
func encodeOptionsSet(templateID uint16, scope templateField, fields []templateField, records [][]byte) []byte {
	recLen := 0
	if len(records) > 0 {
		recLen = len(records[0])
	}
	setLen := 10 + 4*(len(fields)+1) + recLen*len(records) // 头 10B（setID+length+templateID+optCount+scopeCount）
	set := make([]byte, 0, setLen)
	set = binary.BigEndian.AppendUint16(set, ipfixOptionsSetID)
	set = binary.BigEndian.AppendUint16(set, uint16(setLen))
	set = binary.BigEndian.AppendUint16(set, templateID)
	set = binary.BigEndian.AppendUint16(set, uint16(len(fields))) // Options 字段数（不含 scope）
	set = binary.BigEndian.AppendUint16(set, 1)                   // Scope 字段数
	set = binary.BigEndian.AppendUint16(set, scope.ie)
	set = binary.BigEndian.AppendUint16(set, scope.length)
	for _, f := range fields {
		set = binary.BigEndian.AppendUint16(set, f.ie)
		set = binary.BigEndian.AppendUint16(set, f.length)
	}
	for _, r := range records {
		set = append(set, r...)
	}
	return set
}

// samplingOptionsRecord —— System(0) scope + interval/algorithm 单条 options 记录。
func samplingOptionsRecord(algo uint8, interval uint32) []byte {
	b := make([]byte, 0, 9)
	b = binary.BigEndian.AppendUint32(b, 0) // scope value（System）
	b = binary.BigEndian.AppendUint32(b, interval)
	b = append(b, algo)
	return b
}

// encodeDataSet —— 数据集（Set ID = 模板 ID）。
func encodeDataSet(templateID uint16, records [][]byte) []byte {
	setLen := 4
	for _, r := range records {
		setLen += len(r)
	}
	set := make([]byte, 0, setLen)
	set = binary.BigEndian.AppendUint16(set, templateID)
	set = binary.BigEndian.AppendUint16(set, uint16(setLen))
	for _, r := range records {
		set = append(set, r...)
	}
	return set
}

// appendIPFIXSet —— 拼接 Set 到消息体。
func appendIPFIXSet(msg, set []byte) []byte { return append(msg, set...) }
