package decoder

// 华为 NetStream v9 私有 IE 映射（dd/02 §1 定制点 #2）。
//
// fork GoFlow2 落点：v9 模板展开时，enterprise ID = IANAvendorHuawei 的字段先于标准 IE 匹配本表；
// 未识别的私有 IE 计数 `flow_unknown_ie{exporter}`（Prometheus，docs/11 §9：标签白名单 exporter）
// 并保留原始 TLV 透传到 evidence。
//
// 注：dd/02 §1 将本表放于 vendor/huawei.go；因 vendor 目录为 Go 工具链保留语义，
// 骨架实现于 internal/decoder/huawei.go，fork 合入时按 fork 仓库布局挪移。

// IANAvendorHuawei —— Huawei 私有企业号（enterprise ID）。
const IANAvendorHuawei uint32 = 2011

// huaweiIE —— 华为私有 IE 定义（dd/02 §1：field type ≥ 233 的常见项）。
type huaweiIE struct {
	Type uint16
	Name string
	// TODO(fork)：Go 侧映射（目标 FlowRecord 字段 / 透传 evidence 的 TLV 路径）
}

// huaweiIEs —— type → 语义映射。
// TODO(fork)：按华为《NetStream 流量分析功能》资料补齐；已确认候选：
// ingressVRFID、physicalInIfIndex、bytesOut32、destinationInterfaceIndex
// （其中 bytesOut32/destinationInterfaceIndex 的语义可由标准 IE 覆盖，仅华为私有编码差异）。
var huaweiIEs = map[uint16]huaweiIE{}

// mapHuaweiIE —— 返回 (IE 名称, 是否识别)。
func mapHuaweiIE(fieldType uint16) (string, bool) {
	ie, ok := huaweiIEs[fieldType]
	return ie.Name, ok
}
