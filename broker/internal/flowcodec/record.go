// Package flowcodec —— Broker 侧流报文编解码（代理模式专用）。
//
// 边界说明（hld/01 §1）：协议解码属主是 Collector；Broker 仅在 Forwarder 代理
// 重编码路径（dd/01 §4）按需解码/重编码。本包镜像 proto/lucidnet/v1/flowrecord.proto
// 的 proto3 编码（gen/go 生成代码就绪后替换为生成实现，docs/09 §0）。
package flowcodec

import (
	"github.com/SchearLoe/lucidnet/broker/internal/wire"
	"github.com/SchearLoe/lucidnet/shared"
)

// MarshalFlowRecord —— shared.FlowRecord → proto3 字节
// （字段号与 proto/lucidnet/v1/flowrecord.proto 严格一致，零值不编码）。
func MarshalFlowRecord(r *shared.FlowRecord) []byte {
	var w wire.Writer
	w.Int(1, r.TimeStartMs)                       // time_start_ms
	w.Int(2, r.TimeEndMs)                         // time_end_ms
	w.String(3, r.Exporter)                       // exporter
	w.Uint(4, uint64(r.DeviceID))                 // device_id
	w.Uint(5, uint64(r.InIf))                     // in_if
	w.Uint(6, uint64(r.OutIf))                    // out_if
	w.BytesField(7, v4MappedBytes(r.SrcIP))       // src_ip
	w.BytesField(8, v4MappedBytes(r.DstIP))       // dst_ip
	w.Uint(9, uint64(r.SrcPort))                  // src_port
	w.Uint(10, uint64(r.DstPort))                 // dst_port
	w.Uint(11, uint64(r.Proto))                   // proto
	w.Uint(12, uint64(r.IPVersion))               // ip_version
	w.Uint(13, r.Packets)                         // packets
	w.Uint(14, r.Bytes)                           // bytes
	w.Uint(15, uint64(r.TCPFlags))                // tcp_flags
	w.Uint(16, uint64(r.TOS))                     // tos
	w.Uint(17, uint64(r.SampleRate))              // sample_rate
	w.Uint(20, uint64(r.SrcAS))                   // src_as
	w.Uint(21, uint64(r.DstAS))                   // dst_as
	w.BytesField(22, v4MappedBytes(r.BGPNextHop)) // bgp_next_hop
	w.Uint(23, uint64(r.SrcGeo))                  // src_geo
	w.Uint(24, uint64(r.DstGeo))                  // dst_geo
	w.Uint(25, uint64(r.AppID))                   // app_id
	w.Int(26, int64(r.ZoneID))                    // zone_id
	w.Uint(27, uint64(r.IfRole))                  // if_role
	w.Uint(28, uint64(r.ZoneSide))                // zone_side
	return w.Bytes()
}

// UnmarshalFlowRecord —— proto3 字节 → shared.FlowRecord（未知字段跳过，联调/测试用）。
func UnmarshalFlowRecord(b []byte) (shared.FlowRecord, error) {
	var r shared.FlowRecord
	rd := wire.NewReader(b)
	for {
		f, err := rd.Next()
		if err != nil {
			return r, err
		}
		if f.Number == 0 {
			break
		}
		switch f.Number {
		case 1:
			r.TimeStartMs = int64(f.Varint)
		case 2:
			r.TimeEndMs = int64(f.Varint)
		case 3:
			r.Exporter = string(f.Bytes)
		case 4:
			r.DeviceID = uint32(f.Varint)
		case 5:
			r.InIf = uint32(f.Varint)
		case 6:
			r.OutIf = uint32(f.Varint)
		case 7:
			copy16(&r.SrcIP, f.Bytes)
		case 8:
			copy16(&r.DstIP, f.Bytes)
		case 9:
			r.SrcPort = uint32(f.Varint)
		case 10:
			r.DstPort = uint32(f.Varint)
		case 11:
			r.Proto = uint32(f.Varint)
		case 12:
			r.IPVersion = uint32(f.Varint)
		case 13:
			r.Packets = f.Varint
		case 14:
			r.Bytes = f.Varint
		case 15:
			r.TCPFlags = uint32(f.Varint)
		case 16:
			r.TOS = uint32(f.Varint)
		case 17:
			r.SampleRate = uint32(f.Varint)
		case 20:
			r.SrcAS = uint32(f.Varint)
		case 21:
			r.DstAS = uint32(f.Varint)
		case 22:
			copy16(&r.BGPNextHop, f.Bytes)
		case 23:
			r.SrcGeo = uint32(f.Varint)
		case 24:
			r.DstGeo = uint32(f.Varint)
		case 25:
			r.AppID = uint32(f.Varint)
		case 26:
			r.ZoneID = int32(f.Varint)
		case 27:
			r.IfRole = uint8(f.Varint)
		case 28:
			r.ZoneSide = uint8(f.Varint)
		}
	}
	return r, nil
}

// v4MappedBytes —— 16B 数组 → bytes（proto bytes 字段；保持 ::ffff: 映射布局不变）。
func v4MappedBytes(a [16]byte) []byte {
	b := make([]byte, 16)
	copy(b, a[:])
	return b
}

func copy16(dst *[16]byte, src []byte) {
	if len(src) >= 16 {
		copy(dst[:], src[:16])
	}
}
