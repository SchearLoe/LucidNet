/** 状态机徽章（docs/10 §3.1 状态语义：候选=warning、确认=attack 红、处置中=primary、已缓解/关闭=neutral）。 */
import { AttackStatus, ATTACK_STATUS_LABEL } from "@lucid/shared";

const STATUS_CLASS: Record<number, string> = {
  [AttackStatus.CANDIDATE]: "warning",
  [AttackStatus.CONFIRMED]: "attack",
  [AttackStatus.MITIGATING]: "primary",
  [AttackStatus.MITIGATED]: "neutral",
  [AttackStatus.CLOSED]: "neutral",
};

export function StatusBadge({ status }: { status: number }) {
  return <span className={`badge ${STATUS_CLASS[status] ?? "neutral"}`}>{ATTACK_STATUS_LABEL[status] ?? `状态${status}`}</span>;
}

/** 严重度徽章（告警：1提示 2警告 3严重）。 */
export function SeverityBadge({ severity }: { severity: number }) {
  const cls = severity >= 3 ? "attack" : severity === 2 ? "warning" : "neutral";
  const label = severity >= 3 ? "严重" : severity === 2 ? "警告" : "提示";
  return <span className={`badge ${cls}`}>{label}</span>;
}
