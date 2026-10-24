package zone

import "fmt"

// MatchField —— zone_match 匹配面（docs/09 §3：dst|src，默认 dst，禁止 both）。
type MatchField uint8

const (
	// MatchDst —— 默认：客户=被监测方，攻击场景看目的侧（dd/02 §3.3）。
	MatchDst MatchField = iota
	// MatchSrc —— 以“源客户”为监测对象（dd/02 §3.3）。
	MatchSrc
)

// String —— 配置文本（"dst"/"src"）。
func (f MatchField) String() string {
	switch f {
	case MatchSrc:
		return "src"
	default:
		return "dst"
	}
}

// ParseMatchField —— 解析 zone_match 配置；空串取默认 dst（docs/09 §3）。
func ParseMatchField(s string) (MatchField, error) {
	switch s {
	case "", "dst":
		return MatchDst, nil
	case "src":
		return MatchSrc, nil
	default:
		return 0, fmt.Errorf("zone_match %q: %w (want dst|src)", s, ErrInvalidSpec)
	}
}
