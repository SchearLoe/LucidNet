package flowcodec

import (
	"github.com/SchearLoe/lucidnet/shared"
)

// v9/IPFIX 共用 Set/模板解析（RFC 3954 §5.2-§5.3、RFC 7011 §3.2-§3.4.2）：
// 两代协议模板布局同构（差异仅在 set id 与 options 模板头的长度单位），
// 解码侧模板学习/查找统一走 TemplateCache。

// maxRecordsPerSet —— 单数据集记录产出上限（伪造模板+超大包的内存兜底；
// 合法流远不可达：64KB 数据报内 40B 记录约 1600 条）。
const maxRecordsPerSet = 16384

// parsedTemplate —— 模板集内单条模板解析结果。
type parsedTemplate struct {
	id        uint16
	def       *TemplateDef
	withdrawn bool // IPFIX field_count=0 模板撤回（RFC 7011 §3.4.1）
}

// parseFieldSpec —— 单字段说明符（enterprise 位 + 4B PEN，RFC 7011 §3.2）。
func parseFieldSpec(c *binCursor) (TemplateField, bool) {
	ie, ok := c.u16()
	if !ok {
		return TemplateField{}, false
	}
	length, ok := c.u16()
	if !ok {
		return TemplateField{}, false
	}
	f := TemplateField{IE: ie &^ 0x8000, Length: length}
	if ie&0x8000 != 0 {
		pen, ok := c.u32()
		if !ok {
			return TemplateField{}, false
		}
		f.Enterprise = pen
	}
	return f, true
}

// parseDataTemplateSet —— 模板集（set id 0/2）正文 → 模板序列。
func parseDataTemplateSet(body []byte) (defs []parsedTemplate, badSets int) {
	c := binCursor{b: body}
	for c.remain() >= 4 {
		id, _ := c.u16()
		fieldCount, _ := c.u16()
		if id < 256 {
			badSets++ // 模板 ID 0..255 保留
			return
		}
		if fieldCount == 0 {
			defs = append(defs, parsedTemplate{id: id, withdrawn: true})
			continue
		}
		def := &TemplateDef{Fields: make([]TemplateField, 0, fieldCount)}
		for i := 0; i < int(fieldCount); i++ {
			f, ok := parseFieldSpec(&c)
			if !ok {
				badSets++
				return
			}
			def.Fields = append(def.Fields, f)
		}
		defs = append(defs, parsedTemplate{id: id, def: def})
	}
	return defs, badSets
}

// parseOptionsTemplateSet —— options 模板集（set id 1/3）正文。
// v9：scope/option 长度按字节（RFC 3954 §5.3），且数据记录与模板同行内联；
// IPFIX：按字段数（RFC 7011 §3.4.2），数据记录走独立数据集。
// 返回模板定义序列与剩余字节（v9 内联记录，调用方按学习到的模板继续解码）。
func parseOptionsTemplateSet(body []byte, v9 bool) (defs []parsedTemplate, rest []byte, badSets int) {
	c := binCursor{b: body}
	id, ok := c.u16()
	if !ok || id < 256 {
		return nil, nil, 1
	}
	if v9 {
		scopeBytes, _ := c.u16()
		optBytes, ok := c.u16()
		if !ok {
			return nil, nil, 1
		}
		def := &TemplateDef{IsOptions: true}
		// v9 scope 长度按字节：先解析 scope 字段（计数字段按实际解析出的条数，
		// 兼容 vendor PEN 加宽），再解析 option 字段。
		scopeEnd := c.off + int(scopeBytes)
		for c.off < scopeEnd {
			f, ok := parseFieldSpec(&c)
			if !ok || c.off > scopeEnd {
				return nil, nil, 1
			}
			def.ScopeFieldCount++
			def.Fields = append(def.Fields, f)
		}
		optEnd := scopeEnd + int(optBytes)
		for c.off < optEnd {
			f, ok := parseFieldSpec(&c)
			if !ok || c.off > optEnd {
				return nil, nil, 1
			}
			def.Fields = append(def.Fields, f)
		}
		defs = append(defs, parsedTemplate{id: id, def: def})
		return defs, body[c.off:], 0
	}

	fieldCount, ok := c.u16()
	if !ok {
		return nil, nil, 1
	}
	scopeCount, ok := c.u16()
	if !ok || fieldCount == 0 || scopeCount > fieldCount {
		return nil, nil, 1
	}
	def := &TemplateDef{IsOptions: true, ScopeFieldCount: int(scopeCount)}
	for i := 0; i < int(fieldCount); i++ {
		f, ok := parseFieldSpec(&c)
		if !ok {
			return nil, nil, 1
		}
		def.Fields = append(def.Fields, f)
	}
	defs = append(defs, parsedTemplate{id: id, def: def})
	return defs, body[c.off:], 0
}

// fixedRecordLen —— 模板定长记录字节数（含变长字段返回 -1）。
func fixedRecordLen(def *TemplateDef) int {
	total := 0
	for _, f := range def.Fields {
		if f.Length == ieVarlen {
			return -1
		}
		total += int(f.Length)
	}
	return total
}

// minRecordFootprint —— 单记录最小字节数（变长字段按 1B 长度前缀计），
// 数据集尾部迭代终止判据。
func minRecordFootprint(def *TemplateDef) int {
	total := 0
	for _, f := range def.Fields {
		if f.Length == ieVarlen {
			total += 2 // 1B 长度前缀 + 1B 数据（最小有意义变长值）
		} else {
			total += int(f.Length)
		}
	}
	return total
}

// decodeSetRecords —— 数据集正文按模板迭代出统一记录（options 模板记录
// 不产出流记录：仅吸收 systemInitTimeMilliseconds 锚点与全局采样间隔）。
// 尾部 ≤3B 视为 set 对齐 padding（RFC 7011 §3.3.1），更长残尾计 skipped。
func decodeSetRecords(def *TemplateDef, body []byte, tb *timeBase, tc *TemplateCache, key TemplateKey) ([]shared.FlowRecord, DecodeStats) {
	var stats DecodeStats
	var recs []shared.FlowRecord
	c := binCursor{b: body}
	fixed := fixedRecordLen(def)
	minLen := minRecordFootprint(def)
	if minLen <= 0 {
		minLen = 1 // 空模板：无记录语义，循环不启动
	}
	for c.remain() >= minLen && (fixed < 0 || c.remain() >= fixed) && len(recs) < maxRecordsPerSet {
		var rec shared.FlowRecord
		rec.Exporter = key.Exporter
		if !decodeDataRecord(def.Fields, &c, tb, tc, key, &rec) {
			stats.SkippedDataSets++ // 记录截断：整 set 不可信，停止
			return recs, stats
		}
		if def.IsOptions {
			if rec.SampleRate > 0 {
				tc.SetSampleRate(key.Exporter, key.ObsDomain, rec.SampleRate)
			}
			continue
		}
		if rec.SampleRate == 0 {
			if r, ok := tc.SampleRate(key.Exporter, key.ObsDomain); ok {
				rec.SampleRate = r
			}
		}
		if rec.SampleRate == 0 {
			rec.SampleRate = 1 // docs/00：1=全采
		}
		recs = append(recs, rec)
	}
	if r := c.remain(); r >= 4 {
		stats.SkippedDataSets++ // 残尾过长：非对齐 padding，按脏数据计
	}
	return recs, stats
}
