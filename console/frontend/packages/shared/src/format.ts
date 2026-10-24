/**
 * 数字与单位格式化（docs/10 §3.3：前端唯一实现，禁止页面自写）。
 */

const EMPTY = "—";

/** 千分位。 */
function group(intPart: string): string {
  return intPart.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

/** 数量（流/告警/前缀）：千分位；≥1 亿显示 `1.2 亿`（docs/10 §3.3）。 */
export function fmtCount(v: number | null | undefined): string {
  if (v === null || v === undefined || Number.isNaN(v)) return EMPTY;
  if (v >= 1e8) return `${(v / 1e8).toFixed(1)} 亿`;
  return group(Math.round(v).toString());
}

/** SI 词头（十进制）。 */
function siUnit(v: number, units: string[]): { value: number; unit: string } {
  let i = 0;
  let x = v;
  while (x >= 1000 && i < units.length - 1) {
    x /= 1000;
    i += 1;
  }
  return { value: x, unit: units[i] };
}

/** 带宽：SI 十进制 K/M/G/T bps，3 位有效数字（docs/10 §3.3）。 */
export function fmtBps(v: number | null | undefined): string {
  if (v === null || v === undefined || Number.isNaN(v)) return EMPTY;
  if (v === 0) return "0 bps";
  const { value, unit } = siUnit(v, ["bps", "Kbps", "Mbps", "Gbps", "Tbps"]);
  return `${value.toPrecision(3)} ${unit}`;
}

/** 包速率：同 bps 规则，单位 pps。 */
export function fmtPps(v: number | null | undefined): string {
  if (v === null || v === undefined || Number.isNaN(v)) return EMPTY;
  if (v === 0) return "0 pps";
  const { value, unit } = siUnit(v, ["pps", "Kpps", "Mpps", "Gpps"]);
  return `${value.toPrecision(3)} ${unit}`;
}

/** 字节：SI（10³），1 位小数（docs/10 §3.3）。 */
export function fmtBytes(v: number | null | undefined): string {
  if (v === null || v === undefined || Number.isNaN(v)) return EMPTY;
  if (v === 0) return "0 B";
  const { value, unit } = siUnit(v, ["B", "KB", "MB", "GB", "TB"]);
  return `${value.toFixed(1)} ${unit}`;
}

/** 比例：百分比 1 位小数（输入 0-1）。 */
export function fmtRatio(v: number | null | undefined): string {
  if (v === null || v === undefined || Number.isNaN(v)) return EMPTY;
  return `${(v * 100).toFixed(1)}%`;
}

/** 采样加权值标注（docs/10 §3.3：角标 ※，悬浮"按采样率还原的估算值"）。 */
export function sampleMark(sampleRate: number | null | undefined): string {
  return sampleRate && sampleRate > 1 ? "※" : "";
}

/** 绝对时间：YYYY-MM-DD HH:mm:ss（本地时区展示，docs/10 §3.3）。 */
export function fmtTimeMs(ms: number | null | undefined): string {
  if (!ms) return EMPTY;
  const d = new Date(ms);
  const p = (n: number) => n.toString().padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

/** 相对时间（列表），悬浮显示绝对值由调用方 title 承担。 */
export function fmtRelativeMs(ms: number | null | undefined, now = Date.now()): string {
  if (!ms) return EMPTY;
  const diff = Math.max(0, now - ms);
  if (diff < 60_000) return "刚刚";
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} 分钟前`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)} 小时前`;
  return `${Math.floor(diff / 86_400_000)} 天前`;
}
