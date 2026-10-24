package inserter

import (
	"errors"

	"github.com/SchearLoe/lucidnet/shared"
)

// ErrCodecUnavailable —— proto+lz4 解码桩占位错误（gen/ 代码生成就绪后替换，
// docs/09 §0：proto/ 为线格式权威，接口冻结先行）。
var ErrCodecUnavailable = errors.New("proto codec unavailable: gen/lucidnet/v1 codegen not landed yet (docs/09 §0)")

// Codec —— 主题负载解码接口（线格式 = proto+lz4，docs/09 §2）。
type Codec interface {
	DecodeFlowsRaw([]byte) ([]shared.FlowRecord, error)
	DecodeAggrMinuteBatch([]byte) (shared.AggrMinuteBatch, error)
	DecodeAttackMinuteBatch([]byte) (shared.AttackMinuteBatch, error)
	DecodeAlarmEnvelope([]byte) (shared.AlarmEnvelope, error)
}

// ProtoCodec —— proto+lz4 解码桩：walking-skeleton 联调占位（docs/09 §10 联调桩建议）。
// 真实实现待 proto/lucidnet/v1 生成代码（gen/go）+ lz4 解压接入后替换；
// 全部方法当前返回 ErrCodecUnavailable。
type ProtoCodec struct{}

// DecodeFlowsRaw 解码 flows.raw 消息（桩）。
func (ProtoCodec) DecodeFlowsRaw([]byte) ([]shared.FlowRecord, error) {
	return nil, ErrCodecUnavailable
}

// DecodeAggrMinuteBatch 解码 flows.aggr.minute 信封（桩）。
func (ProtoCodec) DecodeAggrMinuteBatch([]byte) (shared.AggrMinuteBatch, error) {
	return shared.AggrMinuteBatch{}, ErrCodecUnavailable
}

// DecodeAttackMinuteBatch 解码 attacks.minutes 信封（桩）。
func (ProtoCodec) DecodeAttackMinuteBatch([]byte) (shared.AttackMinuteBatch, error) {
	return shared.AttackMinuteBatch{}, ErrCodecUnavailable
}

// DecodeAlarmEnvelope 解码 alarms 信封（桩）。
func (ProtoCodec) DecodeAlarmEnvelope([]byte) (shared.AlarmEnvelope, error) {
	return shared.AlarmEnvelope{}, ErrCodecUnavailable
}
