package decoder

import "errors"

// KafkaTemplateWAL —— Kafka + 本地文件模板 WAL 桩（dd/02 §1 定制点 #1）。
//
// 目标行为（fork GoFlow2 时实现）：
//  1. Append：模板变化时先落本地 WAL（fsync），再追加 Kafka `flow.templates`
//     （compact topic，key = exporter+obs_domain，docs/09 §2；消息 = proto TemplateRecord，lz4）；
//  2. Replay：启动时重放本地 WAL 全量 + 尾随合并 Kafka compact log，重建内存模板缓存；
//  3. 与 60s 模板丢失防护联动（环形缓冲回放，goflow2.go replayBuffer）。
type KafkaTemplateWAL struct {
	brokers   []string
	localPath string // 本地 WAL 文件（每节点本地盘）
}

// ErrWALNotImplemented —— 骨架阶段未接通 Kafka/本地 WAL（franz-go 接入后消除）。
var ErrWALNotImplemented = errors.New("kafka template wal not implemented (walking skeleton, dd/02 §1 #1)")

// NewKafkaTemplateWAL —— 构造（brokers Kafka 集群；localPath 本地 WAL 文件路径）。
func NewKafkaTemplateWAL(brokers []string, localPath string) *KafkaTemplateWAL {
	return &KafkaTemplateWAL{brokers: brokers, localPath: localPath}
}

func (w *KafkaTemplateWAL) Append(ev TemplateEvent) error {
	// TODO(franz-go)：本地 WAL fsync → kgo 同步生产 shared.TopicFlowTemplates（compact）
	return ErrWALNotImplemented
}

func (w *KafkaTemplateWAL) Replay() ([]TemplateEvent, error) {
	// TODO(franz-go)：本地 WAL 全量 + Kafka compact log 尾随合并（按 ts 去重）
	return nil, ErrWALNotImplemented
}

func (w *KafkaTemplateWAL) Close() error { return nil }
