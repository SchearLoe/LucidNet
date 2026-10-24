/**
 * 设计 token → ECharts 取值桥（docs/10 §3.1/§4：主题唯一来源，禁止页面内传色值）。
 *
 * 取值顺序：运行时读取 `--lucid-*` CSS 变量（主题切换即时生效）→ 回落
 * LUCID_TOKEN_DEFAULTS（与 packages/shared/tokens.css 逐字对应；深色底 #0A0F1E）。
 * 新增色值一律先落 tokens.css 再同步此处回落值，禁止在组件里写第三份色值。
 */

/** tokens.css 的规范值（回落兜底，SSR/无 DOM 环境仍可用）。 */
export const LUCID_TOKEN_DEFAULTS = {
  primary: "#2f6bff",
  in: "#2f6bff", // 流入（客户视角 in）
  out: "#fa8c16", // 流出（out）
  attack: "#f5222d", // 攻击/严重告警
  baseline: "#8c8c8c", // 基线带
  warning: "#fa8c16",
  success: "#52c41a",
  neutral: "#8c8c8c",
  bg: "#f5f6f8",
  surface: "#ffffff",
  border: "#e5e6eb",
  text: "#1d2129",
  textSecondary: "#4e5969",
  /** 字体（docs/10 §3.2；canvas 不解析 var()，必须取已计算值） */
  fontUi:
    '-apple-system, "Segoe UI", Roboto, "PingFang SC", "Microsoft YaHei", sans-serif',
  fontMono: '"JetBrains Mono", Consolas, "Sarasa Mono SC", monospace',
  /** 深色主题（docs/10 §6 大屏；tokens.css [data-theme="dark"] 同名覆盖） */
  dark: {
    bg: "#0a0f1e",
    surface: "rgba(255, 255, 255, 0.04)",
    border: "rgba(255, 255, 255, 0.08)",
    text: "#e8eaed",
    textSecondary: "#9aa3b2",
  },
} as const;

export type LucidTokens = typeof LUCID_TOKEN_DEFAULTS;

/** 读取元素（默认 :root）上的 --lucid-* 变量；读不到（SSR/测试）用规范值。 */
export function resolveLucidTokens(el?: Element | null, dark = false): LucidTokens {
  const d = LUCID_TOKEN_DEFAULTS;
  const { dark: _dark, ...flat } = d; // 展开扁平 token（dark 子表单独消费）
  const out: Record<string, string> = { ...flat };
  if (typeof document !== "undefined") {
    const cs = getComputedStyle((el ?? document.documentElement) as Element);
    const read = (name: string, fb: string): string => cs.getPropertyValue(name)?.trim() || fb;
    out.primary = read("--lucid-primary", d.primary);
    out.in = read("--lucid-in", d.in);
    out.out = read("--lucid-out", d.out);
    out.attack = read("--lucid-attack", d.attack);
    out.baseline = read("--lucid-baseline", d.baseline);
    out.warning = read("--lucid-warning", d.warning);
    out.success = read("--lucid-success", d.success);
    out.neutral = read("--lucid-neutral", d.neutral);
    const darkSet = dark || read("--lucid-bg", d.bg).toLowerCase() === d.dark.bg;
    if (darkSet) {
      out.bg = read("--lucid-bg", d.dark.bg);
      out.surface = read("--lucid-surface", d.dark.surface);
      out.border = read("--lucid-border", d.dark.border);
      out.text = read("--lucid-text", d.dark.text);
      out.textSecondary = read("--lucid-text-secondary", d.dark.textSecondary);
    } else {
      out.bg = read("--lucid-bg", d.bg);
      out.surface = read("--lucid-surface", d.surface);
      out.border = read("--lucid-border", d.border);
      out.text = read("--lucid-text", d.text);
      out.textSecondary = read("--lucid-text-secondary", d.textSecondary);
    }
    out.fontUi = read("--lucid-font-ui", d.fontUi);
    out.fontMono = read("--lucid-font-mono", d.fontMono);
  } else if (dark) {
    Object.assign(out, d.dark);
  }
  return out as unknown as LucidTokens;
}

/** 透明度合成（带 alpha 的 token 值本身是 rgba，直接叠加会失真，这里统一 color-mix 语义）。 */
export function withAlpha(hexOrRgba: string, alpha: number): string {
  const m = /^#([0-9a-f]{6})$/i.exec(hexOrRgba.trim());
  if (m) {
    const n = parseInt(m[1], 16);
    return `rgba(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255}, ${alpha})`;
  }
  const r = /^rgba?\(([^)]+)\)$/i.exec(hexOrRgba.trim());
  if (r) {
    const parts = r[1].split(/[\s,/]+/).filter(Boolean);
    return `rgba(${parts.slice(0, 3).join(", ")}, ${alpha})`;
  }
  return hexOrRgba;
}
