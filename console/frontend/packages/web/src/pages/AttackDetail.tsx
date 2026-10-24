/**
 * 攻击详情（R5 ★核心，docs/dd/05 §3.2；L2 详情页模板，docs/10 §3.4）：
 * ① 头部摘要卡（攻击ID·客户域·类型·置信度·状态·峰值·目标前缀·起止·Top源）
 * ② 分钟速率曲线（@lucid/charts：bps/pps 双轴 + 基线带 + 攻击起止红带）
 * ③ ★分钟明细表（attack_minutes：bps/pps/newflows/syn比/udp比/Top源/Top端口）
 * ④ 一键处置（R9：POST /api/v1/attacks/{id}/mitigate → LucidBGP，危险操作红色+二次确认）
 */
import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { getAttack, attackMinutes, mitigateAttack } from "../api/client";
import { useStream } from "../stream/useStream";
import { AttackMinuteChart, type MinutePoint } from "@lucid/charts";
import { StatusBadge } from "../components/StatusBadge";
import {
  AttackEvent,
  AttackMinute,
  AttackStatus,
  ATTACK_TYPE_LABEL,
  fmtBps,
  fmtCount,
  fmtPps,
  fmtRatio,
  fmtTimeMs,
} from "@lucid/shared";
import { hasPerm } from "../menus";
import { parsePerms, getToken } from "../api/client";

export function AttackDetail() {
  const { id = "" } = useParams();
  const [attack, setAttack] = useState<AttackEvent | null>(null);
  const [minutes, setMinutes] = useState<AttackMinute[]>([]);
  const [error, setError] = useState("");
  const [traceId, setTraceId] = useState("");
  const [mitigateMsg, setMitigateMsg] = useState("");
  const [mitigating, setMitigating] = useState(false);
  const { events, connected } = useStream("attacks");
  const canHandle = hasPerm(parsePerms(getToken()), "attack:handle");

  const load = useCallback(() => {
    getAttack(id)
      .then((a) => {
        setAttack(a);
        setError("");
      })
      .catch((e) => {
        setError(String(e.message ?? e));
        setTraceId(e.traceId ?? "");
      });
    // 分钟明细由 Storage 点查 CH（未部署时降级提示，不阻塞头部渲染）
    const from = attack?.start_ms ?? 0;
    const to = attack && attack.end_ms > 0 ? attack.end_ms : 0;
    attackMinutes(id, from, to)
      .then((rows) => {
        setMinutes(rows);
      })
      .catch(() => setMinutes([]));
  }, [id, attack?.start_ms, attack?.end_ms]);

  useEffect(load, [load]);
  // WS 推送驱动头部状态刷新（处置中/已缓解状态机推进实时可见）
  useEffect(() => {
    if (events.length > 0) {
      const hit = events.some((e) => (e.data as AttackEvent).attack_id === id);
      if (hit) {
        getAttack(id).then(setAttack).catch(() => undefined);
      }
    }
  }, [events, id]);

  const onMitigate = () => {
    if (!attack) return;
    // 危险操作二次确认（docs/10 §5.1-6）
    if (!window.confirm(`确认对攻击 ${attack.attack_id}（${attack.zone_name || `Zone ${attack.zone_id}`}）下发处置？\n动作将转发 LucidBGP 预填处置表单。`)) {
      return;
    }
    setMitigating(true);
    setMitigateMsg("");
    mitigateAttack(attack.attack_id)
      .then((r) => setMitigateMsg(`已转发 ${r.forwarded}，处置进度见状态机（处置中 → 已缓解）`))
      .catch((e) => setMitigateMsg(`处置失败：${String(e.message ?? e)}`))
      .finally(() => setMitigating(false));
  };

  // 分钟表 → 曲线数据（bps 取入向口径；pps 右轴；基线带待 baseline 回显接线，M2 TODO）
  const points: MinutePoint[] = minutes.map((m) => ({
    ts: m.minute_epoch > 1e11 ? m.minute_epoch : m.minute_epoch * 1000,
    bps: m.bps_in,
    pps: m.pps_in,
    new_flows: m.new_flows,
  }));

  const evidence = parseEvidence(attack?.evidence_json);

  return (
    <div className="content">
      {!connected && <div className="stream-banner">实时推送已断开，正在重连…（状态机以 30s 轮询兜底）</div>}
      {error && (
        <div className="stream-banner">
          {error}
          {traceId && <span className="mono">（trace_id: {traceId}）</span>}
          <button onClick={() => load()}>重试</button>
        </div>
      )}

      {/* ① 头部摘要卡（L2） */}
      <div className="card" style={{ marginTop: 12 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
          <span data-icon="sec-attack" title="lucid-icons: sec-attack" style={{ color: "var(--lucid-attack)" }}>●</span>
          <strong className="mono" style={{ fontSize: "var(--lucid-size-16)" }}>{id}</strong>
          {attack && <StatusBadge status={attack.status} />}
          <div style={{ flex: 1 }} />
          {attack && (
            <Link to="/security/attacks">
              <button type="button">返回列表</button>
            </Link>
          )}
          {attack && canHandle && (
            <button
              type="button"
              className="danger"
              disabled={mitigating || attack.status === AttackStatus.MITIGATED || attack.status === AttackStatus.CLOSED}
              onClick={onMitigate}
            >
              {mitigating ? "处置中…" : "一键处置"}
            </button>
          )}
        </div>
        {mitigateMsg && <div style={{ marginTop: 8, color: "var(--lucid-warning)" }}>{mitigateMsg}</div>}

        {attack && (
          <table className="lucid" style={{ marginTop: 12 }}>
            <tbody>
              <tr>
                <th>客户域</th>
                <td>{attack.zone_name || `Zone ${attack.zone_id}`}</td>
                <th>类型</th>
                <td>{ATTACK_TYPE_LABEL[attack.attack_type] ?? attack.attack_type}</td>
                <th>置信度</th>
                <td className="num">{fmtRatio(attack.confidence)}</td>
              </tr>
              <tr>
                <th>峰值 bps</th>
                <td className="num" style={{ color: "var(--lucid-attack)" }}>{fmtBps(attack.peak_bps)}</td>
                <th>峰值 pps</th>
                <td className="num" style={{ color: "var(--lucid-attack)" }}>{fmtPps(attack.peak_pps)}</td>
                <th>目标前缀</th>
                <td className="mono">{attack.target_prefix || "—"}</td>
              </tr>
              <tr>
                <th>开始时间</th>
                <td className="mono">{fmtTimeMs(attack.start_ms)}</td>
                <th>结束时间</th>
                <td className="mono">{attack.end_ms > 0 ? fmtTimeMs(attack.end_ms) : "—（攻击中）"}</td>
                <th>处置单号</th>
                <td className="mono">{attack.mitigation_id || "—"}</td>
              </tr>
              <tr>
                <th>Top 源</th>
                <td colSpan={5} className="mono">
                  {(attack.top_sources ?? []).length === 0
                    ? "—"
                    : `${attack.top_sources.slice(0, 10).join("，")}${attack.top_sources.length > 10 ? `（等 ${attack.top_sources.length} 个）` : ""}`}
                </td>
              </tr>
              {evidence && (
                <tr>
                  <th>证据快照</th>
                  <td colSpan={5} className="mono" style={{ whiteSpace: "pre-wrap", maxHeight: 160, overflow: "auto" }}>
                    {evidence}
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
      </div>

      {/* ② 分钟速率曲线（R5 ②：双轴 + 基线带 + 攻击起止竖线） */}
      <div className="card" style={{ marginTop: "var(--lucid-gap-card)" }}>
        <h3>分钟速率曲线（bps / pps / 新建流）</h3>
        {points.length === 0 ? (
          <div style={{ color: "var(--lucid-neutral)" }}>
            暂无分钟数据 — attack_minutes 由 Storage 点查 ClickHouse 提供（未部署时此面板为空，头部信息不受影响）
          </div>
        ) : (
          <AttackMinuteChart
            data={points}
            attackStartMs={attack?.start_ms}
            attackEndMs={attack?.end_ms}
            height={340}
          />
        )}
      </div>

      {/* ③ ★分钟明细表（R5 ③） */}
      <div className="card" style={{ marginTop: "var(--lucid-gap-card)" }}>
        <h3>分钟明细（attack_minutes）</h3>
        <table className="lucid">
          <thead>
            <tr>
              <th>分钟</th>
              <th className="num">bps 入</th>
              <th className="num">bps 出</th>
              <th className="num">pps 入</th>
              <th className="num">新建流</th>
              <th className="num">SYN 比</th>
              <th className="num">UDP 比</th>
              <th>Top 源</th>
              <th>Top 端口</th>
            </tr>
          </thead>
          <tbody>
            {minutes.length === 0 && (
              <tr>
                <td colSpan={9} style={{ color: "var(--lucid-neutral)" }}>
                  暂无数据 — 检查攻击时间窗；分钟明细由 Storage（ClickHouse attack_minutes）提供
                </td>
              </tr>
            )}
            {minutes.map((m) => (
              <tr key={m.minute_epoch}>
                <td className="mono">{fmtTimeMs(m.minute_epoch > 1e11 ? m.minute_epoch : m.minute_epoch * 1000)}</td>
                <td className="num">{fmtBps(m.bps_in)}</td>
                <td className="num">{fmtBps(m.bps_out)}</td>
                <td className="num">{fmtPps(m.pps_in)}</td>
                <td className="num">{fmtCount(m.new_flows)}</td>
                <td className="num">{fmtRatio(m.syn_ratio)}</td>
                <td className="num">{fmtRatio(m.udp_ratio)}</td>
                <td className="mono" title={(m.top_sources ?? []).join("，")}>
                  {(m.top_sources ?? []).length === 0 ? "—" : (m.top_sources ?? []).slice(0, 3).join("，")}
                </td>
                <td className="mono">{(m.top_ports ?? []).length === 0 ? "—" : (m.top_ports ?? []).slice(0, 5).join("/")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/** evidence_json 宽容美化（解析失败原样展示）。 */
function parseEvidence(raw: string | undefined): string {
  if (!raw) return "";
  try {
    return JSON.stringify(JSON.parse(raw), null, 2);
  } catch {
    return raw;
  }
}
