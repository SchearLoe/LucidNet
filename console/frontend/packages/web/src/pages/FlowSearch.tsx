/**
 * 明细查询页（R6，docs/dd/05 §2；L1 列表筛选页模板）：
 * 过滤区（时间窗 15m–6h / 客户域 / 方向 / 五元组 / 协议 / IP 版本）→ 结果表
 * （默认 1,000 行，total_estimate >10M 截断提示）→ CSV 导出（接既有异步导出任务流）。
 *
 * 约束文案与网关校验逐字一致（internal/httpapi/flows.go，docs/dd/04 §2.1）：
 * 时间参数 epoch 秒（docs/09 §6 裁定）；>6h 时“查询”按钮变为“创建导出任务”。
 */
import { useCallback, useMemo, useState } from "react";
import { createExportJob, getExportJob, searchFlows } from "../api/client";
import type { ExportJobStatus, FlowFilters, FlowRow } from "@lucid/shared";
import { fmtBytes, fmtCount, fmtTimeMs } from "@lucid/shared";

/** 与网关 flows.go 逐字一致（单一事实源在 Go 侧，前端镜像；改动需双向同步）。 */
const MSG_WINDOW_REQUIRED = "time_start/time_end 必填（epoch 秒）";
const MSG_WINDOW_ORDER = "time_end 必须大于 time_start";
const MSG_WINDOW_OVER = "时间窗超过 6 小时，请改用异步导出任务：POST /api/v1/export/jobs（≤72h）";
const MSG_WINDOW_SMALL = "时间窗过小（最小 1 分钟）";
const MSG_FILTER_REQUIRED = "至少 1 个维度条件（IP/端口/协议/zone/设备/接口）";

const MAX_WINDOW_SEC = 6 * 3600; // R6 同步上限
const PAGE_SIZE = 1000; // dd/04 §2.1 默认 1,000 行

/** 时间窗档位（docs/dd/05 §2：默认 15m，≤6h）。 */
const WINDOWS: Array<{ label: string; sec: number }> = [
  { label: "15 分钟", sec: 900 },
  { label: "30 分钟", sec: 1800 },
  { label: "1 小时", sec: 3600 },
  { label: "3 小时", sec: 3 * 3600 },
  { label: "6 小时（上限）", sec: 6 * 3600 },
];

interface FormState {
  windowSec: number;
  endTimeMode: "now" | "custom";
  endAt: string; // datetime-local（endTimeMode=custom）
  zoneId: string;
  direction: "" | "in" | "out";
  srcIp: string;
  dstIp: string;
  srcPort: string;
  dstPort: string;
  proto: string; // "" | "6" | "17" | "1"
  ipVersion: string; // "" | "4" | "6"
}

const INITIAL: FormState = {
  windowSec: 900,
  endTimeMode: "now",
  endAt: "",
  zoneId: "",
  direction: "",
  srcIp: "",
  dstIp: "",
  srcPort: "",
  dstPort: "",
  proto: "",
  ipVersion: "",
};

/** 组装过滤器（空值不携带；返回 null = 条件不足）。 */
export function buildFilters(f: FormState): FlowFilters | null {
  const filters: FlowFilters = {};
  if (f.srcIp.trim()) filters.src_ip = f.srcIp.trim();
  if (f.dstIp.trim()) filters.dst_ip = f.dstIp.trim();
  if (f.srcPort) filters.src_port = Number(f.srcPort);
  if (f.dstPort) filters.dst_port = Number(f.dstPort);
  if (f.proto) filters.proto = Number(f.proto);
  if (f.zoneId) filters.zone_id = Number(f.zoneId);
  if (f.ipVersion) filters.ip_version = Number(f.ipVersion);
  if (f.direction) filters.direction = f.direction;
  return Object.keys(filters).length > 0 ? filters : null;
}

/** 纯函数校验（与网关 validateFlowSearch 同序同文案；窗口上限不在此拦截——
 * >6h 走导出按钮切换，导出侧另按 ≤72h 校验）。 */
export function validateForm(f: FormState): { filters: FlowFilters; startSec: number; endSec: number; overWindow: boolean } {
  const nowSec = Math.floor(Date.now() / 1000);
  const endSec = f.endTimeMode === "custom" && f.endAt ? Math.floor(new Date(f.endAt).getTime() / 1000) : nowSec;
  const startSec = endSec - f.windowSec;
  if (!(startSec > 0) || !(endSec > 0)) throw new Error(MSG_WINDOW_REQUIRED);
  if (endSec <= startSec) throw new Error(MSG_WINDOW_ORDER);
  if (f.windowSec < 60) throw new Error(MSG_WINDOW_SMALL);
  const filters = buildFilters(f);
  if (!filters) throw new Error(MSG_FILTER_REQUIRED);
  return { filters, startSec, endSec, overWindow: f.windowSec > MAX_WINDOW_SEC };
}

/** 结果行取值（Storage 返回 map 投影；缺失列统一 “—”）。 */
function cell(row: FlowRow, ...keys: string[]): string {
  for (const k of keys) {
    const v = row[k];
    if (v !== undefined && v !== null && v !== "") return String(v);
  }
  return "—";
}

function protoName(p: string): string {
  switch (p) {
    case "6":
      return "TCP";
    case "17":
      return "UDP";
    case "1":
      return "ICMP";
    default:
      return p || "—";
  }
}

const POLL_MS = 2000;

export function FlowSearch() {
  const [form, setForm] = useState<FormState>(INITIAL);
  const [rows, setRows] = useState<FlowRow[]>([]);
  const [total, setTotal] = useState(0);
  const [truncated, setTruncated] = useState(false);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [job, setJob] = useState<ExportJobStatus | null>(null);

  const set = (patch: Partial<FormState>) => setForm((prev) => ({ ...prev, ...patch }));

  const query = useCallback(() => {
    let args: ReturnType<typeof validateForm>;
    try {
      args = validateForm(form);
    } catch (e) {
      setError(String((e as Error).message));
      return;
    }
    setLoading(true);
    setError("");
    if (args.overWindow) {
      // 同步查询硬上限 6h（按钮本应已切换为导出；防御直接回车触发）
      setError(MSG_WINDOW_OVER);
      setLoading(false);
      return;
    }
    searchFlows({
      time_start: args.startSec,
      time_end: args.endSec,
      filters: args.filters,
      page: 1,
      page_size: PAGE_SIZE,
      order_by: "time_start_ms",
      desc: true,
    })
      .then((reply) => {
        setRows(reply.rows ?? []);
        setTotal(reply.total_estimate ?? 0);
        setTruncated((reply.total_estimate ?? 0) > 10_000_000); // >10M 截断（docs/dd/05 §2）
      })
      .catch((e) => {
        setError(String(e.message ?? e));
        setRows([]);
        setTotal(0);
      })
      .finally(() => setLoading(false));
  }, [form]);

  // CSV 导出：镜像当前过滤到异步导出任务（docs/dd/05 §2“添加全部到导出条件”），
  // 轮询任务状态至可下载（产物链接 24h 有效；导出窗口上限 72h，docs/dd/04 §5.1）。
  const exportCsv = useCallback(() => {
    let args: ReturnType<typeof validateForm>;
    try {
      args = validateForm(form);
    } catch (e) {
      setError(String((e as Error).message));
      return;
    }
    if (args.endSec - args.startSec > 72 * 3600) {
      setError("导出窗口超过上限 72h");
      return;
    }
    setJob({ job_id: "", status: "queued" });
    createExportJob({
      type: "flows",
      time_start: args.startSec,
      time_end: args.endSec,
      filters: args.filters,
      format: "csv",
    })
      .then((st) => {
        setJob(st);
        const tick = () => {
          getExportJob(st.job_id)
            .then((cur) => {
              setJob(cur);
              if (cur.status === "queued" || cur.status === "running") setTimeout(tick, POLL_MS);
            })
            .catch((e) => {
              setJob({ job_id: st.job_id, status: "failed", error: String(e.message ?? e) });
            });
        };
        setTimeout(tick, POLL_MS);
      })
      .catch((e) => {
        setJob(null);
        setError(`创建导出任务失败：${String(e.message ?? e)}`);
      });
  }, [form]);

  const overWindow = useMemo(() => form.windowSec > MAX_WINDOW_SEC, [form.windowSec]);

  return (
    <div className="content">
      {error && <div className="stream-banner">{error}</div>}

      {/* 过滤区（L1 模板） */}
      <div className="card" style={{ marginTop: 12 }}>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center" }}>
          <label>
            时间窗{" "}
            <select value={form.windowSec} onChange={(e) => set({ windowSec: Number(e.target.value) })}>
              {WINDOWS.map((w) => (
                <option key={w.sec} value={w.sec}>
                  {w.label}
                </option>
              ))}
            </select>
          </label>
          <label>
            截止{" "}
            <select value={form.endTimeMode} onChange={(e) => set({ endTimeMode: e.target.value as FormState["endTimeMode"] })}>
              <option value="now">当前</option>
              <option value="custom">自定义</option>
            </select>
          </label>
          {form.endTimeMode === "custom" && (
            <input type="datetime-local" value={form.endAt} onChange={(e) => set({ endAt: e.target.value })} />
          )}
          <input placeholder="客户域 ID" value={form.zoneId} onChange={(e) => set({ zoneId: e.target.value.replace(/\D/g, "") })} style={{ width: 110 }} />
          <label>
            方向{" "}
            <select value={form.direction} onChange={(e) => set({ direction: e.target.value as FormState["direction"] })}>
              <option value="">全部</option>
              <option value="in">流入（in）</option>
              <option value="out">流出（out）</option>
            </select>
          </label>
          <input placeholder="源 IP/前缀" value={form.srcIp} onChange={(e) => set({ srcIp: e.target.value })} style={{ width: 150 }} className="mono" />
          <input placeholder="目的 IP/前缀" value={form.dstIp} onChange={(e) => set({ dstIp: e.target.value })} style={{ width: 150 }} className="mono" />
          <input placeholder="源端口" value={form.srcPort} onChange={(e) => set({ srcPort: e.target.value.replace(/\D/g, "") })} style={{ width: 90 }} className="mono" />
          <input placeholder="目的端口" value={form.dstPort} onChange={(e) => set({ dstPort: e.target.value.replace(/\D/g, "") })} style={{ width: 90 }} className="mono" />
          <label>
            协议{" "}
            <select value={form.proto} onChange={(e) => set({ proto: e.target.value })}>
              <option value="">全部</option>
              <option value="6">TCP</option>
              <option value="17">UDP</option>
              <option value="1">ICMP</option>
            </select>
          </label>
          <label>
            IP 版本{" "}
            <select value={form.ipVersion} onChange={(e) => set({ ipVersion: e.target.value })}>
              <option value="">全部</option>
              <option value="4">IPv4</option>
              <option value="6">IPv6</option>
            </select>
          </label>

          {/* >6h：查询按钮变为“创建导出任务”（docs/dd/05 §2 交互约束） */}
          {overWindow ? (
            <button onClick={exportCsv} disabled={job?.status === "queued" || job?.status === "running"}>
              创建导出任务
            </button>
          ) : (
            <button onClick={query} disabled={loading}>
              {loading ? "查询中…" : "查询"}
            </button>
          )}
          <button onClick={exportCsv} disabled={job?.status === "queued" || job?.status === "running"} data-icon="flow-export" title="lucid-icons: flow-export">
            导出 CSV（异步任务）
          </button>
        </div>
        <div style={{ marginTop: 8, fontSize: 12, color: "var(--lucid-text-secondary)" }}>
          同步查询时间窗上限 6 小时（超过请用异步导出任务，窗口 ≤72h）；至少 1 个维度条件（IP/端口/协议/客户域）；限流 10 QPS/用户。
        </div>

        {job && (
          <div style={{ marginTop: 8, fontSize: 13 }}>
            导出任务 <span className="mono">{job.job_id || "…"}</span>{" "}
            {job.status === "done" ? (
              job.url ? (
                <a href={job.url} target="_blank" rel="noreferrer">下载产物（链接 24 小时内有效）</a>
              ) : (
                <span>已完成（产物链接未返回）</span>
              )
            ) : job.status === "failed" ? (
              <span style={{ color: "var(--lucid-attack)" }}>失败：{job.error ?? "未知错误"}</span>
            ) : (
              <span>
                {job.status === "running" ? `执行中 ${Math.round((job.progress ?? 0) * 100)}%` : "排队中"}（每 {POLL_MS / 1000}s 自动刷新）
              </span>
            )}
          </div>
        )}
      </div>

      {/* 结果表 */}
      <div className="card" style={{ marginTop: "var(--lucid-gap-card)" }}>
        <h3>
          明细结果（默认前 {fmtCount(PAGE_SIZE)} 行）
          {truncated && <span style={{ color: "var(--lucid-warning)", marginLeft: 8 }}>总数超过 1,000 万，仅返回前 {fmtCount(PAGE_SIZE)} 行，完整结果请创建导出任务</span>}
        </h3>
        <table className="lucid">
          <thead>
            <tr>
              <th>开始</th>
              <th>协议</th>
              <th>源 IP</th>
              <th className="num">源端口</th>
              <th>目的 IP</th>
              <th className="num">目的端口</th>
              <th className="num">包数</th>
              <th className="num">字节</th>
              <th>flags</th>
              <th className="num">入/出接口</th>
              <th className="num">采样率</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && !loading && (
              <tr>
                <td colSpan={11} style={{ color: "var(--lucid-neutral)" }}>
                  暂无数据 — 检查过滤条件/时间窗；或上游 Storage 明细查询服务未部署（R6，docs/09 §6）
                </td>
              </tr>
            )}
            {rows.map((r, i) => (
              <tr key={i}>
                <td className="mono">{r.time_start_ms ? fmtTimeMs(r.time_start_ms) : cell(r, "start", "time_start")}</td>
                <td>{protoName(cell(r, "proto"))}</td>
                <td className="mono">{cell(r, "src_ip", "src")}</td>
                <td className="num">{cell(r, "src_port", "sport")}</td>
                <td className="mono">{cell(r, "dst_ip", "dst")}</td>
                <td className="num">{cell(r, "dst_port", "dport")}</td>
                <td className="num">{cell(r, "packets", "pkts")}</td>
                <td className="num">{typeof r.bytes === "number" ? fmtBytes(r.bytes) : cell(r, "bytes")}</td>
                <td className="mono">{cell(r, "tcp_flags", "flags")}</td>
                <td className="num">{cell(r, "in_if")}/{cell(r, "out_if")}</td>
                <td className="num">{cell(r, "sample_rate", "sample")}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {rows.length > 0 && (
          <div style={{ marginTop: 8, color: "var(--lucid-neutral)", fontSize: 13 }}>
            估算命中 {fmtCount(total)} 行{truncated ? "（>10M 截断）" : ""}；本页显示 {rows.length} 行（page 1/{PAGE_SIZE}）
          </div>
        )}
      </div>
    </div>
  );
}
