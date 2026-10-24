package fsm

import "github.com/SchearLoe/lucidnet/shared"

// State —— 攻击状态机状态（dd/03 §6.1）。
// 注意：dd/03 §6.1 中的 RECOVERED/RESOLVED 在 shared.AttackStatus 枚举中无对应值，
// 映射关系见 State.AttackStatus（契约差异已记录模块 README/报告）。
type State uint8

const (
	StateNone       State = 0 // 无活跃攻击
	StateCandidate  State = 1 // 候选
	StateConfirmed  State = 2 // 确认
	StateMitigating State = 3 // 处置中（R9 回执联动）
	StateRecovered  State = 4 // 已恢复（保持展示 60s 后关闭）
	StateResolved   State = 5 // 处置后速率回落，已缓解（终态）
	StateClosed     State = 6 // 恢复关闭 / 候选静默关闭（终态）
)

func (s State) String() string {
	switch s {
	case StateNone:
		return "none"
	case StateCandidate:
		return "candidate"
	case StateConfirmed:
		return "confirmed"
	case StateMitigating:
		return "mitigating"
	case StateRecovered:
		return "recovered"
	case StateResolved:
		return "resolved"
	case StateClosed:
		return "closed"
	default:
		return "unknown"
	}
}

// AttackStatus —— 映射到 shared.AttackStatus（09 §2 枚举，跨模块唯一权威）：
//   - CANDIDATE→AttackCandidate，CONFIRMED→AttackConfirmed；
//   - RECOVERED 无枚举值：保持 AttackConfirmed 展示，直至 CLOSED→AttackClosed
//     （dd/03 §6.1 "保持展示60s后关闭"）；
//   - RESOLVED→AttackMitigated（已缓解）。
func (s State) AttackStatus() shared.AttackStatus {
	switch s {
	case StateCandidate:
		return shared.AttackCandidate
	case StateConfirmed, StateRecovered:
		return shared.AttackConfirmed
	case StateMitigating:
		return shared.AttackMitigating
	case StateResolved:
		return shared.AttackMitigated
	case StateClosed:
		return shared.AttackClosed
	default:
		return 0
	}
}
