/** 攻击中心列表（L1 列表筛选页，docs/dd/05 §3.1：攻击中置顶、WS 实时、CSV 导出；行点击进 R5 详情）。 */
import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { listAttacks } from "../api/client";
import { useStream } from "../stream/useStream";
import { StatusBadge } from "../components/StatusBadge";
import {
  AttackEvent,
  ATTACK_TYPE_LABEL,
  fmtBps,
  fmtPps,
  fmtRatio,
  fmtRelativeMs,
  fmtTimeMs,
} from "@lucid/shared";

const PAGE_SIZE = 20;

export function AttackList() {
  const [rows, setRows] = useState<AttackEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [zoneId, setZoneId] = useState("");
  const [error, setError] = useState("");
  const { events, connected } = useStream("attacks");

  const load = useCallback(() => {
    listAttacks({
      page,
      page_size: PAGE_SIZE,
      zone_id: zoneId ? Number(zoneId) : undefined,
    })
      .then((p) => {
        setRows(p.rows);
        setTotal(p.total);
        setError("");
      })
      .catch((e) => setError(String(e.message ?? e)));
  }, [page, zoneId]);

  useEffect(load, [load]);
  // WS 推送驱动刷新（推送延迟预算 ≤2s，docs/hld/05 §5）。
  useEffect(() => {
    if (events.length > 0) load();
  }, [events, load]);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div className="content">
      {!connected && <div className="stream-banner">实时推送已断开，正在重连…（列表退化为 30s 轮询）</div>}
      {error && <div className="stream-banner">{error}</div>}

      <div className="card" style={{ marginTop: 12 }}>
        {/* 过滤区（L1 模板：docs/10 §3.4） */}
        <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
          <input
            placeholder="客户域 ID（0/空=全部）"
            value={zoneId}
            onChange={(e) => {
              setPage(1);
              setZoneId(e.target.value.replace(/\D/g, ""));
            }}
            style={{ width: 200 }}
          />
          <button onClick={() => load()}>查询</button>
          <a href={`/api/v1/attacks?format=csv${zoneId ? `&zone_id=${zoneId}` : ""}`}>
            <button type="button">CSV 导出</button>
          </a>
        </div>

        <table className="lucid">
          <thead>
            <tr>
              <th>攻击ID</th>
              <th>客户域</th>
              <th>类型</th>
              <th className="num">峰值 bps</th>
              <th className="num">峰值 pps</th>
              <th className="num">置信度</th>
              <th>开始时间</th>
              <th>状态</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && (
              <tr>
                <td colSpan={9} style={{ color: "var(--lucid-neutral)" }}>
                  暂无攻击记录 — 检查过滤条件/时间窗；攻击事件经网关 WS（alarms 主题）实时进入
                </td>
              </tr>
            )}
            {rows.map((a) => (
              <tr key={a.attack_id}>
                <td className="mono" title={a.attack_id}>
                  {a.attack_id.length > 14 ? `${a.attack_id.slice(0, 14)}…` : a.attack_id}
                </td>
                <td>{a.zone_name || `Zone ${a.zone_id}`}</td>
                <td>{ATTACK_TYPE_LABEL[a.attack_type] ?? a.attack_type}</td>
                <td className="num">{fmtBps(a.peak_bps)}</td>
                <td className="num">{fmtPps(a.peak_pps)}</td>
                <td className="num">{fmtRatio(a.confidence)}</td>
                <td className="mono" title={fmtTimeMs(a.start_ms)}>
                  {fmtRelativeMs(a.start_ms)}
                </td>
                <td>
                  <StatusBadge status={a.status} />
                </td>
                <td>
                  <Link to={`/security/attacks/${encodeURIComponent(a.attack_id)}`} style={{ color: "var(--lucid-primary)" }}>
                    详情
                  </Link>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        <div style={{ display: "flex", gap: 8, marginTop: 12, alignItems: "center" }}>
          <button disabled={page <= 1} onClick={() => setPage(page - 1)}>
            上一页
          </button>
          <span className="mono">
            {page} / {totalPages}（共 {total} 条）
          </span>
          <button disabled={page >= totalPages} onClick={() => setPage(page + 1)}>
            下一页
          </button>
        </div>
      </div>
    </div>
  );
}
