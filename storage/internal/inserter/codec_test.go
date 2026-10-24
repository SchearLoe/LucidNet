package inserter

import (
	"errors"
	"testing"
)

// TestProtoCodecStub —— 解码桩全部返回 ErrCodecUnavailable（docs/09 §0 接口冻结）。
func TestProtoCodecStub(t *testing.T) {
	var c Codec = ProtoCodec{}
	if _, err := c.DecodeFlowsRaw(nil); !errors.Is(err, ErrCodecUnavailable) {
		t.Errorf("flows.raw err = %v", err)
	}
	if _, err := c.DecodeAggrMinuteBatch(nil); !errors.Is(err, ErrCodecUnavailable) {
		t.Errorf("aggr err = %v", err)
	}
	if _, err := c.DecodeAttackMinuteBatch(nil); !errors.Is(err, ErrCodecUnavailable) {
		t.Errorf("attacks err = %v", err)
	}
	if _, err := c.DecodeAlarmEnvelope(nil); !errors.Is(err, ErrCodecUnavailable) {
		t.Errorf("alarms err = %v", err)
	}
}
