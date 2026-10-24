/**
 * REST 客户端（docs/00 §6：/api/v1 前缀、JWT Bearer、{code,msg,data} 信封）。
 * token 存 localStorage；生产签发走 Master /api/v1/auth/*（M1 联调支持粘贴
 * `lucid-gateway -dev-token` 产出的 JWT）。
 */
import type {
  Envelope,
  Page,
  AttackEvent,
  Alarm,
  AttackMinute,
  ZoneTraffic,
  FlowSearchRequest,
  FlowSearchReply,
  ExportJobRequest,
  ExportJobStatus,
} from "@lucid/shared";

const TOKEN_KEY = "lucid_token";

export function getToken(): string {
  return localStorage.getItem(TOKEN_KEY) ?? "";
}

export function setToken(tok: string): void {
  localStorage.setItem(TOKEN_KEY, tok.trim());
}

/** 解析 JWT payload 的 perms（不验签，仅用于前端控件显隐；接口层仍由网关强制）。 */
export function parsePerms(tok: string): string[] {
  try {
    const payload = JSON.parse(atob(tok.split(".")[1]?.replace(/-/g, "+").replace(/_/g, "/") ?? "{}"));
    return Array.isArray(payload.perms) ? payload.perms : [];
  } catch {
    return [];
  }
}

export class ApiError extends Error {
  constructor(readonly code: number, msg: string, readonly traceId?: string) {
    super(msg);
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  const tok = getToken();
  if (tok) headers.Authorization = `Bearer ${tok}`;
  const resp = await fetch(path, { ...init, headers });
  const body = (await resp.json()) as Envelope<T>;
  if (resp.status === 401) {
    throw new ApiError(401, "未认证，请在页头粘贴访问令牌（dev-token）", body.trace_id);
  }
  if (body.code !== 0) {
    throw new ApiError(resp.status, body.msg, body.trace_id);
  }
  return body.data;
}

/** R7：攻击列表（攻击中置顶）。 */
export function listAttacks(params: {
  page?: number;
  page_size?: number;
  zone_id?: number;
  status?: number;
}): Promise<Page<AttackEvent>> {
  const q = new URLSearchParams();
  if (params.page) q.set("page", String(params.page));
  if (params.page_size) q.set("page_size", String(params.page_size));
  if (params.zone_id) q.set("zone_id", String(params.zone_id));
  if (params.status) q.set("status", String(params.status));
  return request<Page<AttackEvent>>(`/api/v1/attacks?${q}`);
}

/** R7：告警列表。 */
export function listAlarms(params: { page?: number; page_size?: number }): Promise<Page<Alarm>> {
  const q = new URLSearchParams();
  if (params.page) q.set("page", String(params.page));
  if (params.page_size) q.set("page_size", String(params.page_size));
  return request<Page<Alarm>>(`/api/v1/alarms?${q}`);
}

/** R2：客户域实时视图。 */
export function zoneRealtime(): Promise<ZoneTraffic[]> {
  return request<ZoneTraffic[]>("/api/v1/zones/realtime");
}

/** R5：攻击详情头部（含 evidence_json 特征快照）。 */
export function getAttack(attackId: string): Promise<AttackEvent> {
  return request<AttackEvent>(`/api/v1/attacks/${encodeURIComponent(attackId)}`);
}

/** R5：攻击分钟明细（Storage 点查 CH attack_minutes；窗口参数与网关现有 from_ms/to_ms 一致）。 */
export function attackMinutes(attackId: string, fromMs?: number, toMs?: number): Promise<AttackMinute[]> {
  const q = new URLSearchParams();
  if (fromMs) q.set("from_ms", String(fromMs));
  if (toMs) q.set("to_ms", String(toMs));
  const qs = q.toString();
  return request<AttackMinute[]>(`/api/v1/attacks/${encodeURIComponent(attackId)}/minutes${qs ? `?${qs}` : ""}`);
}

/** R9：一键处置（转发 LucidBGP 预填处置表单；需 attack:handle）。 */
export function mitigateAttack(attackId: string): Promise<{ attack_id: string; forwarded: string }> {
  return request(`/api/v1/attacks/${encodeURIComponent(attackId)}/mitigate`, { method: "POST" });
}

/** R6：明细查询（网关 10 QPS/用户限流；时间窗 ≤6h，epoch 秒）。 */
export function searchFlows(req: FlowSearchRequest): Promise<FlowSearchReply> {
  return request<FlowSearchReply>("/api/v1/flows/search", { method: "POST", body: JSON.stringify(req) });
}

/** R5/R6：创建异步导出任务（窗口 ≤72h；产物链接 24h 有效）。 */
export function createExportJob(req: ExportJobRequest): Promise<ExportJobStatus> {
  return request<ExportJobStatus>("/api/v1/export/jobs", { method: "POST", body: JSON.stringify(req) });
}

/** R5/R6：导出任务状态/进度/下载链接轮询。 */
export function getExportJob(jobId: string): Promise<ExportJobStatus> {
  return request<ExportJobStatus>(`/api/v1/export/jobs/${encodeURIComponent(jobId)}`);
}
