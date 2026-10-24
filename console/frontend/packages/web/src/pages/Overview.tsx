/** 总览（大屏深色，docs/10 §6：无滚动单屏、KPI 数字 24px 等宽、WS 告警滚动）。 */
import { useEffect, useState } from "react";
import { zoneRealtime, listAttacks, listAlarms } from "../api/client";
import { useStream } from "../stream/useStream";
import { fmtBps, fmtPps, fmtRelativeMs } from "@lucid/shared";
import type { AttackEvent, Alarm, ZoneTraffic } from "@lucid/shared";
import { SeverityBadge } from "../components/StatusBadge";

export function Overview() {
  const [zones, setZones] = useState<ZoneTraffic[]>([]);
  const [attacks, setAttacks] = useState<AttackEvent[]>([]);
  const [alarms, setAlarms] = useState<Alarm[]>([]);
  const [error, setError] = useState("");
  const { events, connected } = useStream("events");

  useEffect(() => {
    const tick = () => {
      zoneRealtime().then(setZones).catch((e) => setError(String(e.message ?? e)));
      listAttacks({ page: 1, page_size: 8 })
        .then((p) => setAttacks(p.rows))
        .catch(() => undefined);
      listAlarms({ page: 1, page_size: 8 })
        .then((p) => setAlarms(p.rows))
        .catch(() => undefined);
    };
    tick();
    const id = setInterval(tick, 5_000); // docs/10 §6：刷新 ≥5s 且显示数据时间戳
    return () => clearInterval(id);
  }, []);

  const totalIn = zones.reduce((s, z) => s + z.bps_in, 0);
  const totalOut = zones.reduce((s, z) => s + z.bps_out, 0);
  const ongoing = zones.reduce((s, z) => s + z.ongoing, 0);

  return (
    <div className="content theme-dark" style={{ minHeight: "calc(100vh - var(--lucid-header-h))" }}>
      {!connected && (
        <div className="stream-banner">实时推送已断开，正在重连…（最近快照每 5 秒刷新）</div>
      )}
      {error && <div className="stream-banner">{error}</div>}
      <div className="grid-kpi" style={{ marginTop: 12 }}>
        <div className="card kpi">
          <div className="label">全网流入（客户视角 in）</div>
          <div className="value in">{fmtBps(totalIn)}</div>
        </div>
        <div className="card kpi">
          <div className="label">全网流出（out）</div>
          <div className="value out">{fmtBps(totalOut)}</div>
        </div>
        <div className="card kpi">
          <div className="label">攻击中客户域</div>
          <div className="value attack">{ongoing}</div>
        </div>
        <div className="card kpi">
          <div className="label">接入客户域</div>
          <div className="value">{zones.length}</div>
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "var(--lucid-gap-card)", marginTop: "var(--lucid-gap-card)" }}>
        <div className="card">
          <h3>实时告警（WS 推送）</h3>
          <table className="lucid">
            <thead>
              <tr>
                <th>级别</th>
                <th>主题</th>
                <th>时间</th>
              </tr>
            </thead>
            <tbody>
              {events.length === 0 && alarms.length === 0 && (
                <tr>
                  <td colSpan={3} style={{ color: "var(--lucid-neutral)" }}>暂无告警 — 保持此页打开即可接收实时推送</td>
                </tr>
              )}
              {events.slice(0, 8).map((e, i) => {
                const a = e.data as Alarm;
                return (
                  <tr key={`${e.ts_ms}-${i}`}>
                    <td>{e.type === "alarm" ? <SeverityBadge severity={a.severity} /> : <span className="badge primary">事件</span>}</td>
                    <td>{e.type === "alarm" ? a.subject : `${e.type} ${a.attack_id ?? ""}`}</td>
                    <td className="mono">{fmtRelativeMs(e.ts_ms)}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
        <div className="card">
          <h3>客户域实时速率（5s 轮询）</h3>
          <table className="lucid">
            <thead>
              <tr>
                <th>客户域</th>
                <th className="num">流入</th>
                <th className="num">流出</th>
                <th className="num">攻击中</th>
              </tr>
            </thead>
            <tbody>
              {zones.length === 0 && (
                <tr>
                  <td colSpan={4} style={{ color: "var(--lucid-neutral)" }}>暂无数据 — 等待 Analytics 实时键（rt:*）接入</td>
                </tr>
              )}
              {zones.map((z) => (
                <tr key={z.zone_id}>
                  <td>{z.zone_name || `Zone ${z.zone_id}`}</td>
                  <td className="num in" style={{ color: "var(--lucid-in)" }}>{fmtBps(z.bps_in)}</td>
                  <td className="num" style={{ color: "var(--lucid-out)" }}>{fmtBps(z.bps_out)}</td>
                  <td className="num">{z.ongoing > 0 ? <span className="badge attack">{z.ongoing}</span> : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="card" style={{ marginTop: "var(--lucid-gap-card)" }}>
        <h3>最新攻击（R2/R7）</h3>
        <table className="lucid">
          <thead>
            <tr>
              <th>攻击ID</th>
              <th>客户域</th>
              <th className="num">峰值 bps</th>
              <th className="num">峰值 pps</th>
              <th>开始时间</th>
            </tr>
          </thead>
          <tbody>
            {attacks.length === 0 && (
              <tr>
                <td colSpan={5} style={{ color: "var(--lucid-neutral)" }}>暂无攻击记录 — 攻击经 alarms 主题实时进入</td>
              </tr>
            )}
            {attacks.map((a) => (
              <tr key={a.attack_id}>
                <td className="mono">{a.attack_id}</td>
                <td>{a.zone_name}</td>
                <td className="num">{fmtBps(a.peak_bps)}</td>
                <td className="num">{fmtPps(a.peak_pps)}</td>
                <td className="mono">{fmtRelativeMs(a.start_ms)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
