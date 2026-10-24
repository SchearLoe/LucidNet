/**
 * 契约类型（docs/00 §2 / docs/09 §2 的 proto JSON 镜像）。
 * TODO(M2)：以 buf generate 生成 gen/ts 类型替换本手写镜像（docs/dd/05 §1，
 * 生成前禁止改动字段名——与 proto JSON snake_case 严格一致）。
 */

/** 攻击类型（shared.AttackType 枚举镜像）。 */
export enum AttackType {
  SYN_FLOOD = 1,
  UDP_FLOOD = 2,
  ACK_FLOOD = 3,
  ICMP_FLOOD = 4,
  REFLECTION = 5,
  SWEEP = 6, // 扫段（R7）
  ANOMALY = 7, // 流量波动告警（R7）
  UNKNOWN = 8,
}

/** 攻击状态机（shared.AttackStatus 镜像；docs/10 §3.1 状态语义配色）。 */
export enum AttackStatus {
  CANDIDATE = 1,
  CONFIRMED = 2,
  MITIGATING = 3,
  MITIGATED = 4,
  CLOSED = 5,
}

export interface AttackEvent {
  attack_id: string;
  zone_id: number;
  zone_name: string;
  attack_type: number;
  target_prefix: string;
  start_ms: number;
  end_ms: number;
  peak_bps: number;
  peak_pps: number;
  confidence: number; // 0-1
  top_sources: string[];
  evidence_json: string;
  status: number;
  mitigation_id: string;
}

export interface Alarm {
  alarm_id: string;
  source: string; // analytics|bgp|system
  severity: number; // 1提示 2警告 3严重
  category: number; // 攻击/波动/设备/系统
  raise_ms: number;
  clear_ms: number;
  subject: string;
  detail_json: string;
  zone_id: number;
  attack_id: string;
}

export interface AttackMinute {
  attack_id: string;
  minute_epoch: number;
  bps_in: number;
  pps_in: number;
  bps_out: number;
  pps_out: number;
  new_flows: number;
  syn_ratio: number;
  udp_ratio: number;
  top_sources: string[];
  top_ports: number[];
}

/** 客户域实时流量视图行（R2）。 */
export interface ZoneTraffic {
  zone_id: number;
  zone_name: string;
  bps_in: number;
  bps_out: number;
  pps_in: number;
  pps_out: number;
  attack_count: number;
  ongoing: number;
  sample_rate: number;
  ts_ms: number;
}

/** 统一响应信封（docs/00 §6 {code,msg,data}，附加 trace_id）。 */
export interface Envelope<T> {
  code: number;
  msg: string;
  data: T;
  trace_id?: string;
}

export interface Page<T> {
  rows: T[];
  total: number;
}

/** R6 维度过滤（docs/dd/04 §2.1 白名单：≥1 个条件，≤8 个；与 upstream.FlowFilters 镜像）。 */
export interface FlowFilters {
  src_ip?: string; // IP 或 CIDR
  dst_ip?: string;
  src_port?: number;
  dst_port?: number;
  proto?: number;
  zone_id?: number;
  device_id?: number;
  in_if?: number;
  out_if?: number;
  ip_version?: number; // R3：4/6
  /** 方向（客户视角 in/out；M1 网关契约未登记，前端先传、Storage 落地后生效）。 */
  direction?: "in" | "out";
}

/** R6 明细查询请求（docs/dd/04 §2.2；时间参数 epoch 秒，docs/09 §6 裁定）。 */
export interface FlowSearchRequest {
  time_start: number;
  time_end: number;
  filters: FlowFilters;
  order_by?: string;
  desc?: boolean;
  page?: number;
  page_size?: number;
  fields?: string[];
  cursor?: unknown;
}

/** R6 查询响应（total_estimate 超 1,000 万由 Storage 截断提示）。 */
export interface FlowSearchReply {
  total_estimate: number;
  rows: FlowRow[];
  query_id: string;
  cursor?: unknown;
}

/** 结果行（Storage 返回 map[string]any；已知列按 FlowRecord JSON 投影，防御性读取）。 */
export interface FlowRow {
  time_start_ms?: number;
  time_end_ms?: number;
  start?: string;
  end?: string;
  src_ip?: string;
  dst_ip?: string;
  src_port?: number;
  dst_port?: number;
  proto?: number;
  packets?: number;
  bytes?: number;
  tcp_flags?: number | string;
  in_if?: number;
  out_if?: number;
  sample_rate?: number;
  zone_id?: number;
  direction?: string;
  [key: string]: unknown;
}

/** R5/R6 异步导出任务请求（docs/dd/04 §5.1；窗口 ≤72h）。 */
export interface ExportJobRequest {
  type: "flows" | "attack_flows" | "aggr" | "attacks";
  attack_id?: string;
  time_start: number;
  time_end: number;
  filters?: FlowFilters;
  format?: "text" | "csv" | "jsonl";
  sample?: "raw" | "downscale_10x";
}

/** 导出任务状态（docs/00 §6：产物落 MinIO，链接 24h 有效）。 */
export interface ExportJobStatus {
  job_id: string;
  status: "queued" | "running" | "done" | "failed";
  progress?: number;
  url?: string;
  expires_at?: number;
  error?: string;
}

/** 攻击类型展示名（docs/10 §5.3 术语表唯一权威）。 */
export const ATTACK_TYPE_LABEL: Record<number, string> = {
  [AttackType.SYN_FLOOD]: "SYN Flood",
  [AttackType.UDP_FLOOD]: "UDP Flood",
  [AttackType.ACK_FLOOD]: "ACK Flood",
  [AttackType.ICMP_FLOOD]: "ICMP Flood",
  [AttackType.REFLECTION]: "反射攻击",
  [AttackType.SWEEP]: "扫段攻击",
  [AttackType.ANOMALY]: "流量波动告警",
  [AttackType.UNKNOWN]: "未知",
};

/** 攻击状态展示名。 */
export const ATTACK_STATUS_LABEL: Record<number, string> = {
  [AttackStatus.CANDIDATE]: "候选",
  [AttackStatus.CONFIRMED]: "确认",
  [AttackStatus.MITIGATING]: "处置中",
  [AttackStatus.MITIGATED]: "已缓解",
  [AttackStatus.CLOSED]: "已关闭",
};
