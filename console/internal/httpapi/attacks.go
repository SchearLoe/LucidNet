package httpapi

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"

	"github.com/SchearLoe/lucidnet/console/internal/query"
	"github.com/SchearLoe/lucidnet/console/internal/upstream"
	"github.com/SchearLoe/lucidnet/shared"
)

// 攻击类型/状态展示名（shared 枚举镜像；术语以 docs/10 §5.3 为唯一权威）。
var attackTypeNames = map[shared.AttackType]string{
	shared.AttackSYNFlood:   "SYN_FLOOD",
	shared.AttackUDPFlood:   "UDP_FLOOD",
	shared.AttackACKFlood:   "ACK_FLOOD",
	shared.AttackICMPFlood:  "ICMP_FLOOD",
	shared.AttackReflection: "REFLECTION",
	shared.AttackSweep:      "SWEEP",
	shared.AttackAnomaly:    "ANOMALY",
	shared.AttackUnknown:    "UNKNOWN",
}

var attackStatusNames = map[shared.AttackStatus]string{
	shared.AttackCandidate:  "candidate",
	shared.AttackConfirmed:  "confirmed",
	shared.AttackMitigating: "mitigating",
	shared.AttackMitigated:  "mitigated",
	shared.AttackClosed:     "closed",
}

// zoneRealtime —— GET /api/v1/zones/realtime（R2 客户域 DDoS 实时视图；
// 数据源 = Redis rt:* TopN 近端快照，docs/00 §6）。
func (h *Handlers) zoneRealtime() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rows, err := h.Zones.ZoneRealtime(r.Context())
		if err != nil {
			writeAPIError(w, r, err, "客户域实时视图查询")
			return
		}
		writeOK(w, r, rows)
	})
}

// listAttacks —— GET /api/v1/attacks（R7 列表：攻击中置顶、按置信度/速率排序；
// 支持 zone_id/type/status/from_ms/to_ms 过滤与 format=csv 导出，docs/dd/05 §3.1）。
func (h *Handlers) listAttacks() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f := query.AttackFilter{
			ZoneID: atoi32(r.URL.Query().Get("zone_id")),
		}
		for _, v := range r.URL.Query()["type"] {
			if n, err := strconv.ParseUint(v, 10, 32); err == nil {
				f.Types = append(f.Types, shared.AttackType(n))
			}
		}
		for _, v := range r.URL.Query()["status"] {
			if n, err := strconv.ParseUint(v, 10, 32); err == nil {
				f.Statuses = append(f.Statuses, shared.AttackStatus(n))
			}
		}
		f.FromMs = atoi64(r.URL.Query().Get("from_ms"))
		f.ToMs = atoi64(r.URL.Query().Get("to_ms"))
		f.Page, f.PageSize = pageParams(r)

		pageData, err := h.Attacks.ListAttacks(r.Context(), f)
		if err != nil {
			writeAPIError(w, r, err, "攻击列表查询")
			return
		}
		if r.URL.Query().Get("format") == "csv" {
			h.writeAttacksCSV(w, r, pageData.Rows)
			return
		}
		writeOK(w, r, pageData)
	})
}

// getAttack —— GET /api/v1/attacks/{attack_id}（R5 详情头部 + 证据）。
func (h *Handlers) getAttack() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("attack_id")
		a, err := h.Attacks.GetAttack(r.Context(), id)
		if err != nil {
			writeAPIError(w, r, err, "攻击详情查询 "+id)
			return
		}
		writeOK(w, r, a)
	})
}

// attackMinutes —— GET /api/v1/attacks/{attack_id}/minutes（R5 ★分钟明细表；
// 提供方 Storage 点查 CH attack_minutes，docs/dd/04 §3）。
func (h *Handlers) attackMinutes() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("attack_id")
		fromMs := atoi64(r.URL.Query().Get("from_ms"))
		toMs := atoi64(r.URL.Query().Get("to_ms"))
		rows, err := h.Storage.AttackMinutes(r.Context(), id, fromMs, toMs)
		if err != nil {
			writeAPIError(w, r, err, "攻击分钟明细查询 "+id)
			return
		}
		writeOK(w, r, rows)
	})
}

// mitigate —— POST /api/v1/attacks/{attack_id}/mitigate（R9 一键处置：
// 转发 LucidBGP POST /api/bgp/alarms 预填处置表单，docs/dd/05 §5）。
func (h *Handlers) mitigate() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("attack_id")
		a, err := h.Attacks.GetAttack(r.Context(), id)
		if err != nil {
			writeAPIError(w, r, err, "攻击详情查询 "+id)
			return
		}
		if err := h.BGP.ForwardAlarm(r.Context(), upstream.MitigateRequest{
			AttackID:   a.AttackID,
			ZoneID:     a.ZoneID,
			ZoneName:   a.ZoneName,
			TopSources: a.TopSources,
		}); err != nil {
			writeAPIError(w, r, err, "一键处置转发 LucidBGP")
			return
		}
		// TODO(R9)：记录处置轨迹审计（mitigations 回执由 WS 流承担）。
		writeOK(w, r, map[string]string{"attack_id": id, "forwarded": "lucid-bgp"})
	})
}

// writeAttacksCSV —— R7 列表 CSV 导出（UTF-8 BOM 便于 Excel 中文）。
func (h *Handlers) writeAttacksCSV(w http.ResponseWriter, r *http.Request, rows []*shared.AttackEvent) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="attacks.csv"`)
	if _, err := w.Write([]byte{0xEF, 0xBB, 0xBF}); err != nil {
		return
	}
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"attack_id", "zone_id", "zone_name", "type", "status", "target_prefix",
		"start_ms", "end_ms", "peak_bps", "peak_pps", "confidence", "mitigation_id"})
	for _, a := range rows {
		_ = cw.Write([]string{
			a.AttackID, strconv.FormatInt(int64(a.ZoneID), 10), a.ZoneName,
			attackTypeNames[a.AttackType], attackStatusNames[a.Status], a.TargetPrefix,
			strconv.FormatInt(a.StartMs, 10), strconv.FormatInt(a.EndMs, 10),
			strconv.FormatInt(a.PeakBps, 10), strconv.FormatInt(a.PeakPps, 10),
			fmt.Sprintf("%.2f", a.Confidence), a.MitigationID,
		})
	}
	cw.Flush()
}
