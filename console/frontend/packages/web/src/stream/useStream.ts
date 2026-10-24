/**
 * useStream —— WS 实时流（docs/00 §6 /api/v1/stream/{topic}）。
 * 断线自动重连（2s 起指数退避至 30s 封顶）；断连状态供黄条提示（docs/10 §3.7）。
 */
import { useEffect, useRef, useState } from "react";
import type { Alarm, AttackEvent } from "@lucid/shared";
import { getToken } from "../api/client";

export type StreamTopic = "alarms" | "attacks" | "events";

export interface StreamEvent {
  topic: string;
  type: "alarm" | "attack" | "mitigation";
  zone_id?: number;
  ts_ms: number;
  data: Alarm | AttackEvent | Record<string, unknown>;
}

export interface StreamState {
  events: StreamEvent[];
  connected: boolean;
}

export function useStream(topic: StreamTopic, zoneId = 0, capacity = 200): StreamState {
  const [events, setEvents] = useState<StreamEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const retryMs = useRef(2000);

  useEffect(() => {
    let ws: WebSocket | null = null;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let closed = false;

    const connect = () => {
      const proto = location.protocol === "https:" ? "wss:" : "ws:";
      const url = `${proto}//${location.host}/api/v1/stream/${topic}?access_token=${encodeURIComponent(getToken())}&zone_id=${zoneId}`;
      ws = new WebSocket(url);
      ws.onopen = () => {
        setConnected(true);
        retryMs.current = 2000;
      };
      ws.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data) as StreamEvent;
          setEvents((prev) => {
            const next = [msg, ...prev];
            return next.length > capacity ? next.slice(0, capacity) : next;
          });
        } catch {
          // 非 JSON 帧忽略
        }
      };
      ws.onclose = () => {
        setConnected(false);
        if (!closed) timer = setTimeout(connect, retryMs.current);
        retryMs.current = Math.min(retryMs.current * 2, 30_000);
      };
      ws.onerror = () => ws?.close();
    };

    connect();
    return () => {
      closed = true;
      if (timer) clearTimeout(timer);
      ws?.close();
    };
  }, [topic, zoneId, capacity]);

  return { events, connected };
}
