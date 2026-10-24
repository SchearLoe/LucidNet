// Package ws —— WebSocket 升级与泵出（docs/00 §6：/api/v1/stream/alarms|attacks|events，
// 由网关提供）。读端只处理客户端 ping/close；下行由 hub 信箱驱动。
package ws

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/websocket"

	"github.com/SchearLoe/lucidnet/console/internal/hub"
)

// Topic 校验：允许的流订阅主题（docs/00 §6 路径枚举）。
var topics = map[string]string{
	"alarms":  "alarms",
	"attacks": "attacks",
	"events":  "events",
}

// ValidTopic 报文主题是否允许订阅。
func ValidTopic(t string) bool { _, ok := topics[t]; return ok }

// Handler —— 单 topic 流 handler（path /api/v1/stream/{topic}）。
type Handler struct {
	hub       *hub.Hub
	upgrader  websocket.Upgrader
	log       *slog.Logger
	writeWait  time.Duration
	pongWait   time.Duration
}

// NewHandler 构造。
func NewHandler(h *hub.Hub, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.Default()
	}
	return &Handler{
		hub:      h,
		upgrader: websocket.Upgrader{ReadBufferSize: 1024, WriteBufferSize: 4096},
		log:      log,
		writeWait: 10 * time.Second,
		pongWait:  60 * time.Second,
	}
}

// CheckOrigin —— 同源默认 + 开发期放开（生产应由反代约束来源，TODO M2 校验白名单）。
func (h *Handler) CheckOrigin(r *http.Request) bool { return true }

// ServeStream 处理 GET /api/v1/stream/{topic}（鉴权已由外层中间件完成）。
func (h *Handler) ServeStream(w http.ResponseWriter, r *http.Request) {
	topic := r.PathValue("topic")
	if !ValidTopic(topic) {
		http.Error(w, `{"code":404,"msg":"unknown stream topic","data":null}`, http.StatusNotFound)
		return
	}
	h.upgrader.CheckOrigin = h.CheckOrigin
	conn, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.log.Warn("ws upgrade failed", "module", "gateway", "err", err)
		return
	}
	client := hub.NewClient(parseZone(r), 64)
	h.hub.Subscribe(client)
	h.log.Info("ws subscribed", "module", "gateway", "topic", topic, "zone_id", client.ZoneID)

	defer func() {
		h.hub.Unsubscribe(client)
		client.Close()
		_ = conn.Close()
		h.log.Info("ws closed", "module", "gateway", "topic", topic)
	}()

	// 写超时控制 + ping 保活。
	_ = conn.SetWriteDeadline(time.Now().Add(h.writeWait))
	_ = conn.SetReadDeadline(time.Now().Add(h.pongWait))
	conn.SetPongHandler(func(string) error {
		return conn.SetReadDeadline(time.Now().Add(h.pongWait))
	})

	// 读端：仅消费控制帧（close/ping），业务上行 M1 无。
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		for {
			if _, _, err := conn.NextReader(); err != nil {
				return
			}
		}
	}()

	ticker := time.NewTicker(h.pongWait / 2)
	defer ticker.Stop()

	for {
		select {
		case <-client.Closed():
			return
		case <-readDone:
			return
		case <-ticker.C:
			_ = conn.SetWriteDeadline(time.Now().Add(h.writeWait))
			if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		case msg := <-client.Send:
			_ = conn.SetWriteDeadline(time.Now().Add(h.writeWait))
			payload, err := json.Marshal(msg)
			if err != nil {
				h.log.Error("ws marshal message", "module", "gateway", "err", err)
				continue
			}
			if err := conn.WriteMessage(websocket.TextMessage, payload); err != nil {
				return
			}
		}
	}
}

func parseZone(r *http.Request) int32 {
	z, err := strconv.ParseInt(r.URL.Query().Get("zone_id"), 10, 32)
	if err != nil {
		return 0
	}
	return int32(z)
}
