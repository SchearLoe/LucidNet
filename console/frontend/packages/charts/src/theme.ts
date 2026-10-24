/**
 * lucid ECharts 主题（docs/10 §3.6：主题唯一来源；§4：运行时读取 CSS 变量生成，
 * 深/浅两主题一致；语义色 = --lucid-* token：入蓝/出橙/攻击红，深色底）。
 */
import * as echarts from "echarts/core";
import { resolveLucidTokens, withAlpha, type LucidTokens } from "./tokens";

export const LUCID_THEME_LIGHT = "lucid";
export const LUCID_THEME_DARK = "lucid-dark";

/** 由 token 生成主题对象（docs/10 §3.6：网格线仅横向、图例左上、tooltip 十字准线）。 */
export function createLucidTheme(dark = false, el?: Element | null): Record<string, unknown> {
  const t: LucidTokens = resolveLucidTokens(el, dark);
  const textColor = dark ? t.text : t.textSecondary;
  const subText = t.textSecondary;
  return {
    color: [t.in, t.out, t.attack, t.success, t.warning, t.primary, t.neutral],
    backgroundColor: "transparent", // 底色交给页面（卡片/大屏各自承担）
    textStyle: { color: textColor, fontFamily: t.fontUi },
    legend: { textStyle: { color: subText }, left: "left", itemWidth: 14, itemHeight: 8 },
    tooltip: {
      axisPointer: { type: "cross", lineStyle: { color: withAlpha(t.neutral, 0.6) }, crossStyle: { color: withAlpha(t.neutral, 0.6) } },
      backgroundColor: dark ? "#141a2e" : t.surface,
      borderColor: t.border,
      textStyle: { color: dark ? t.text : "#1d2129" },
    },
    categoryAxis: {
      axisLine: { lineStyle: { color: t.border } },
      axisTick: { show: false },
      axisLabel: { color: subText },
      splitLine: { show: false },
    },
    valueAxis: {
      axisLine: { show: false },
      axisTick: { show: false },
      axisLabel: { color: subText },
      splitLine: { show: true, lineStyle: { color: t.border, type: "solid" } }, // 仅横向网格
    },
    timeAxis: {
      axisLine: { lineStyle: { color: t.border } },
      axisTick: { show: false },
      axisLabel: { color: subText, hideOverlap: true },
      splitLine: { show: true, lineStyle: { color: t.border, type: "solid" } },
    },
    line: { symbol: "none", lineWidth: 1.5 },
    bar: { itemStyle: { borderRadius: [2, 2, 0, 0] } },
  };
}

const registered = new Set<string>();

/** 注册（幂等）并返回主题名，供 echarts.init(container, name) 使用。 */
export function ensureLucidTheme(dark = false, el?: Element | null): string {
  const name = dark ? LUCID_THEME_DARK : LUCID_THEME_LIGHT;
  if (!registered.has(name)) {
    echarts.registerTheme(name, createLucidTheme(dark, el));
    registered.add(name);
  }
  return name;
}

/** 主题重算（token 变更/主题切换后调用；重复注册同名即覆盖）。 */
export function refreshLucidTheme(dark = false, el?: Element | null): string {
  const name = dark ? LUCID_THEME_DARK : LUCID_THEME_LIGHT;
  echarts.registerTheme(name, createLucidTheme(dark, el));
  registered.add(name);
  return name;
}
