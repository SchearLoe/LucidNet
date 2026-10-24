/**
 * AttackMinuteChart —— 攻击详情分钟速率曲线（R5 ★核心，docs/dd/05 §3.2-② /
 * docs/10 §3.6 图表规范）：
 *   - 左轴带宽 bps（入蓝 --lucid-in），右轴 pps/new_flows（出橙 --lucid-out，可选）；
 *   - 基线带：中位数灰实线 + ±MAD 半透明带（数据点带 baseline / baseline_mad 时渲染）；
 *   - 攻击起止：红色半透明竖带 + 起止标注（attackStartMs / attackEndMs）；
 *   - 采样曲线副标题标注“※ 估算（采样率 N:1）”（docs/10 §3.6）；
 *   - tooltip 十字准线；网格线仅横向；色值全部来自 lucid 主题（token 桥）。
 */
import { useEffect, useMemo, useRef } from "react";
// 按需注册（避免全量 echarts 进 bundle；docs/11 工程化原则）
import * as echarts from "echarts/core";
import { BarChart, LineChart } from "echarts/charts";
import {
  GridComponent,
  LegendComponent,
  MarkAreaComponent,
  MarkLineComponent,
  TooltipComponent,
} from "echarts/components";
import { CanvasRenderer } from "echarts/renderers";
import type { EChartsType } from "echarts/core";
import { ensureLucidTheme, refreshLucidTheme } from "./theme";
import { resolveLucidTokens, withAlpha } from "./tokens";

echarts.use([
  LineChart,
  BarChart,
  GridComponent,
  TooltipComponent,
  LegendComponent,
  MarkLineComponent,
  MarkAreaComponent,
  CanvasRenderer,
]);

/** 分钟数据点（与 GET /api/v1/attacks/{id}/minutes 及 baseline 回显对齐的展示投影）。 */
export interface MinutePoint {
  /** 分钟起点，epoch 毫秒（attack_minutes.minute_epoch × 1000）。 */
  ts: number;
  /** 带宽 bps（bps_in，或 bps_in+bps_out 由调用方决定口径）。 */
  bps: number;
  /** 基线中位数 bps（可选；缺省不画基线带）。 */
  baseline?: number;
  /** 基线半带宽 = MAD（可选；缺省 0 → 带退化为线）。 */
  baseline_mad?: number;
  /** 包速率 pps（可选，右轴）。 */
  pps?: number;
  /** 新建流/分（可选，右轴）。 */
  new_flows?: number;
}

export interface AttackMinuteChartProps {
  data: MinutePoint[];
  /** 深色主题（大屏/总览嵌用；默认浅色）。 */
  dark?: boolean;
  /** 攻击起止（epoch 毫秒；起止都有画红色竖带，单侧画竖线）。 */
  attackStartMs?: number;
  attackEndMs?: number;
  /** 采样率（>1 时副标题标注 ※ 估算）。 */
  sampleRate?: number;
  /** 图表高度（默认 320）。 */
  height?: number;
  /** 右轴序列开关（数据含 pps/new_flows 时启用；默认 true）。 */
  showPps?: boolean;
}

interface BuildOpts {
  attackStartMs: number;
  attackEndMs: number;
  sampleRate: number;
  showPps: boolean;
}

/** ECharts option 组装（导出供测试/故事书复用；色值经 token 桥，禁止页面传色值）。 */
export function buildAttackMinuteOption(points: MinutePoint[], opts: BuildOpts): echarts.EChartsCoreOption {

  const t = resolveLucidTokens(null, false);
  const sorted = [...points].sort((a, b) => a.ts - b.ts);
  const hasBand = sorted.some((p) => (p.baseline ?? 0) > 0 && (p.baseline_mad ?? 0) > 0);
  const hasBaseline = sorted.some((p) => (p.baseline ?? 0) > 0);
  const hasPps = opts.showPps && sorted.some((p) => (p.pps ?? 0) > 0);
  const hasFlows = opts.showPps && sorted.some((p) => (p.new_flows ?? 0) > 0);

  const legend: string[] = [];
  if (hasBaseline) legend.push("基线");
  if (hasPps) legend.push("pps");
  if (hasFlows) legend.push("新建流");

  const series: Record<string, unknown>[] = [];

  if (hasBand) {
    // 基线带（stack 技法：低值隐形 + 2×MAD 半透明带；docs/10 §3.6 基线带画法）
    series.push(
      {
        name: "__band_low",
        type: "line",
        stack: "baseline-band",
        data: sorted.map((p) => [p.ts, Math.max(0, (p.baseline ?? 0) - (p.baseline_mad ?? 0))]),
        lineStyle: { opacity: 0 },
        symbol: "none",
        silent: true,
        tooltip: { show: false },
      },
      {
        name: "__band_fill",
        type: "line",
        stack: "baseline-band",
        data: sorted.map((p) => [p.ts, 2 * (p.baseline_mad ?? 0)]),
        lineStyle: { opacity: 0 },
        areaStyle: { color: withAlpha(t.baseline, 0.18) },
        symbol: "none",
        silent: true,
        tooltip: { show: false },
      },
    );
  }

  const mainSeries: Record<string, unknown> = {
    name: "bps",
    type: "line",
    smooth: false,
    sampling: "lttb",
    lineStyle: { color: t.in, width: 1.5 },
    itemStyle: { color: t.in },
    data: sorted.map((p) => [p.ts, p.bps]),
    emphasis: { focus: "series" },
  };

  // 攻击起止（R5：红色半透明竖带 + 起止标注）
  if (opts.attackStartMs > 0 && opts.attackEndMs > opts.attackStartMs) {
    mainSeries.markArea = {
      silent: true,
      itemStyle: { color: withAlpha(t.attack, 0.08) },
      label: { color: t.attack },
      data: [[{ name: "攻击时段", xAxis: opts.attackStartMs }, { xAxis: opts.attackEndMs }]],
    };
  } else {
    const marks: Record<string, unknown>[] = [];
    if (opts.attackStartMs > 0) marks.push({ xAxis: opts.attackStartMs, label: { formatter: "开始", color: t.attack } });
    if (opts.attackEndMs > 0) marks.push({ xAxis: opts.attackEndMs, label: { formatter: "结束", color: t.attack } });
    if (marks.length > 0) {
      mainSeries.markLine = {
        silent: true,
        symbol: "none",
        lineStyle: { color: t.attack, type: "solid", width: 1 },
        label: { position: "insideEndTop" },
        data: marks,
      };
    }
  }
  series.push(mainSeries);

  if (hasBaseline) {
    series.push({
      name: "基线",
      type: "line",
      data: sorted.map((p) => [p.ts, p.baseline ?? 0]),
      lineStyle: { color: t.baseline, type: "dashed", width: 1 },
      itemStyle: { color: t.baseline },
      symbol: "none",
    });
  }

  if (hasPps) {
    series.push({
      name: "pps",
      type: "line",
      yAxisIndex: 1,
      sampling: "lttb",
      lineStyle: { color: t.out, width: 1 },
      itemStyle: { color: t.out },
      data: sorted.map((p) => [p.ts, p.pps ?? 0]),
    });
  }
  if (hasFlows) {
    series.push({
      name: "新建流",
      type: "bar",
      yAxisIndex: 1,
      barWidth: "60%",
      itemStyle: { color: withAlpha(t.out, 0.35) },
      data: sorted.map((p) => [p.ts, p.new_flows ?? 0]),
    });
  }

  const rightAxis = hasPps || hasFlows;
  return {
    animation: false,
    grid: { left: 56, right: rightAxis ? 56 : 20, top: 36, bottom: 28 },
    legend: legend.length > 0 ? { data: legend } : { show: false },
    tooltip: { trigger: "axis", axisPointer: { type: "cross" } },
    xAxis: { type: "time" },
    yAxis: [
      { type: "value", name: "bps", axisLabel: { formatter: (v: number) => fmtAxis(v) } },
      ...(rightAxis
        ? [{ type: "value", name: hasFlows ? "pps / 流" : "pps", splitLine: { show: false }, axisLabel: { formatter: (v: number) => fmtAxis(v) } }]
        : []),
    ],
    series,
  };
}

/** 轴标签速率缩写（K/M/G；完整格式化归 shared/format.ts，此处仅轴空间优化）。 */
function fmtAxis(v: number): string {
  if (v === 0) return "0";
  const units = ["", "K", "M", "G", "T"];
  let i = 0;
  let x = v;
  while (x >= 1000 && i < units.length - 1) {
    x /= 1000;
    i += 1;
  }
  return `${x >= 100 ? Math.round(x) : x.toPrecision(3)}${units[i]}`;
}

export function AttackMinuteChart({
  data,
  dark = false,
  attackStartMs = 0,
  attackEndMs = 0,
  sampleRate,
  height = 320,
  showPps = true,
}: AttackMinuteChartProps) {
  const elRef = useRef<HTMLDivElement | null>(null);
  const chartRef = useRef<EChartsType | null>(null);

  const option = useMemo(
    () => buildAttackMinuteOption(data, { attackStartMs, attackEndMs, sampleRate: sampleRate ?? 1, showPps }),
    [data, attackStartMs, attackEndMs, sampleRate, showPps],
  );

  useEffect(() => {
    const el = elRef.current;
    if (!el) return;
    const theme = ensureLucidTheme(dark, el);
    const chart = echarts.init(el, theme);
    chartRef.current = chart;
    const ro = new ResizeObserver(() => chart.resize());
    ro.observe(el);
    return () => {
      ro.disconnect();
      chart.dispose();
      chartRef.current = null;
    };
  }, [dark]);

  useEffect(() => {
    if (chartRef.current) {
      // token 运行时切换后重注册同名主题并整体替换 option
      refreshLucidTheme(dark, elRef.current ?? undefined);
      chartRef.current.setOption(option, true);
    }
  }, [option, dark]);

  const subtitle = sampleRate && sampleRate > 1 ? `※ 估算（采样率 ${sampleRate}:1）` : "";

  return (
    <div>
      {subtitle && (
        <div style={{ fontSize: 12, color: "var(--lucid-text-secondary)", marginBottom: 4 }}>{subtitle}</div>
      )}
      <div ref={elRef} style={{ width: "100%", height }} role="img" aria-label="攻击分钟速率曲线" />
    </div>
  );
}
