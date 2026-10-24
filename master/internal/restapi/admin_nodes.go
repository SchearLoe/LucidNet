package restapi

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/SchearLoe/lucidnet/master/internal/assign"
	"github.com/SchearLoe/lucidnet/master/internal/registry"
)

// 节点与拓扑查询（docs/dd/07 §1 REST：/api/v1/admin/nodes*）+ exporter 台账 + 分配表。

func (s *Server) handleListNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.d.Registry.List(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, 500, "list nodes failed")
		return
	}
	if nodes == nil {
		nodes = []registry.Node{}
	}
	writeOK(w, nodes)
}

func (s *Server) handleGetNode(w http.ResponseWriter, r *http.Request) {
	n, err := s.d.Registry.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, registry.ErrNotFound) {
			writeErr(w, http.StatusNotFound, 404, "node not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, 500, "get node failed")
		return
	}
	writeOK(w, n)
}

// handleDrainNode 排水（docs/dd/07 §2：分配表摘除 → 迁移完成（lag 归零）→ 允许维护；
// 迁移完成自动判定 M2，需人工确认后置 maintenance）。
func (s *Server) handleDrainNode(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !s.requireLeader(w, r) {
		return
	}
	if err := s.d.Registry.Drain(r.Context(), id); err != nil {
		writeErr(w, http.StatusInternalServerError, 500, "drain failed: "+err.Error())
		return
	}
	// 同步排水命令（组件侧停接收新流量/去注册，docs/dd/07 §1 下行命令）
	payload, _ := json.Marshal(map[string]any{"node": id, "reason": "manual drain"})
	_ = s.d.Hub.Push(id, Cmd{Type: "drain", PayloadJSON: string(payload), CreatedAt: s.now()})
	s.recordAudit(r, "node.drain", "node:"+id, string(payload), "drain node")
	writeOK(w, map[string]string{"id": id, "state": string(registry.StateDraining)})
}

type setStateReq struct {
	State string `json:"state"`
}

func (s *Server) handleSetNodeState(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req setStateReq
	if err := decodeBody(r, &req); err != nil || !registry.ValidState(registry.State(req.State)) {
		writeErr(w, http.StatusBadRequest, 400, "state must be online|draining|maintenance|offline")
		return
	}
	if !s.requireLeader(w, r) {
		return
	}
	if err := s.d.Registry.SetState(r.Context(), id, registry.State(req.State)); err != nil {
		writeErr(w, http.StatusInternalServerError, 500, "set state failed: "+err.Error())
		return
	}
	s.recordAudit(r, "node.state", "node:"+id, `{"state":"`+req.State+`"}`, "set node state")
	writeOK(w, map[string]string{"id": id, "state": req.State})
}

type setWeightReq struct {
	Weight float64 `json:"weight"`
}

func (s *Server) handleSetWeight(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req setWeightReq
	if err := decodeBody(r, &req); err != nil || req.Weight < 0 {
		writeErr(w, http.StatusBadRequest, 400, "weight must be >= 0 (0=auto)")
		return
	}
	if !s.requireLeader(w, r) {
		return
	}
	if err := s.d.Registry.SetWeightOverride(r.Context(), id, req.Weight); err != nil {
		writeErr(w, http.StatusInternalServerError, 500, "set weight failed: "+err.Error())
		return
	}
	s.recordAudit(r, "node.weight", "node:"+id,
		`{"weight":`+jsonFloat(req.Weight)+`}`, "set weight override")
	writeOK(w, map[string]any{"id": id, "weight_override": req.Weight})
}

// handleListExporters exporter 台账。
func (s *Server) handleListExporters(w http.ResponseWriter, r *http.Request) {
	list, err := s.d.Registry.Exporters(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, 500, "list exporters failed")
		return
	}
	if list == nil {
		list = []registry.Exporter{}
	}
	writeOK(w, list)
}

type upsertExporterReq struct {
	IP        string `json:"ip"`
	DeviceID  uint32 `json:"device_id"`
	ActiveSet bool   `json:"active_set"`
	PinnedTo  string `json:"pinned_to,omitempty"`
}

// handleUpsertExporter 管理侧登记 exporter（分配输入）。
func (s *Server) handleUpsertExporter(w http.ResponseWriter, r *http.Request) {
	var req upsertExporterReq
	if err := decodeBody(r, &req); err != nil || req.IP == "" {
		writeErr(w, http.StatusBadRequest, 400, "ip required")
		return
	}
	if !s.requireLeader(w, r) {
		return
	}
	if err := s.d.Registry.RecordExporter(r.Context(), registry.Exporter{
		IP: req.IP, DeviceID: req.DeviceID, ActiveSet: req.ActiveSet, PinnedTo: req.PinnedTo,
	}); err != nil {
		writeErr(w, http.StatusInternalServerError, 500, "upsert exporter failed")
		return
	}
	s.recordAudit(r, "exporter.upsert", "exporter:"+req.IP, `{"active_set":true}`, "")
	writeOK(w, req)
}

// handleAssignTable 当前分配表（集群拓扑/状态查询 API）。
func (s *Server) handleAssignTable(w http.ResponseWriter, r *http.Request) {
	t := s.d.Assigner.Current()
	if t.Entries == nil {
		t.Entries = []assign.Entry{}
	}
	writeOK(w, t)
}

type pinReq struct {
	Exporter  string `json:"exporter"`
	Collector string `json:"collector"` // 空=解除 pin
}

// handleAssignPin 手工 pin（docs/dd/07 §3 触发条件：手工 pin）。
func (s *Server) handleAssignPin(w http.ResponseWriter, r *http.Request) {
	var req pinReq
	if err := decodeBody(r, &req); err != nil || req.Exporter == "" {
		writeErr(w, http.StatusBadRequest, 400, "exporter required")
		return
	}
	if !s.requireLeader(w, r) {
		return
	}
	if err := s.d.Registry.PinExporter(r.Context(), req.Exporter, req.Collector); err != nil {
		writeErr(w, http.StatusInternalServerError, 500, "pin failed: "+err.Error())
		return
	}
	s.recordAudit(r, "assign.pin", "exporter:"+req.Exporter,
		`{"collector":"`+req.Collector+`"}`, "pin exporter")
	writeOK(w, req)
}

// requireLeader 写操作 leader 门禁（备机只读保护，docs/dd/07 §7）。
func (s *Server) requireLeader(w http.ResponseWriter, r *http.Request) bool {
	if s.d.Leader != nil && !s.d.Leader() {
		writeErr(w, http.StatusServiceUnavailable, 503, "not leader: cluster is read-only")
		return false
	}
	return true
}

func jsonFloat(f float64) string {
	b, _ := json.Marshal(f)
	return string(b)
}
