package zone

import (
	"encoding/json"
	"fmt"
	"net/netip"
)

// ParseSpecsJSON —— /lucid/zones **信封内 data 负载**解析（JSON 镜像 proto ZoneSpec，
// docs/09 §5）。裸 payload 入口已收进信封路径之后：调用方须先经 internal/etcdcfg
// 解信封（09 §5 2026-10-25 裁定），本函数只解析 Envelope.Data。
// 生产路径：etcd watch → etcdcfg.Decode → 版本守卫 → 本函数 → Matcher.Update
// （≤2s 生效 SLA，docs/09 §5）。
func ParseSpecsJSON(data []byte) ([]ZoneSpec, error) {
	var raw []zoneSpecJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse zones json: %w", err)
	}
	specs := make([]ZoneSpec, 0, len(raw))
	for _, r := range raw {
		z := ZoneSpec{ID: r.ID, Name: r.Name, Tenant: r.Tenant, PolicyID: r.PolicyID}
		for _, p := range r.IPs {
			e, err := ipEntryFromCIDR(p.Prefix)
			if err != nil {
				return nil, fmt.Errorf("zone %d: %w", r.ID, err)
			}
			z.IPs = append(z.IPs, e)
		}
		for _, d := range r.BoundaryIFs {
			z.BoundaryIFs = append(z.BoundaryIFs, DeviceIf{DeviceID: d.DeviceID, IfIndex: d.IfIndex})
		}
		specs = append(specs, z)
	}
	return specs, nil
}

type zoneSpecJSON struct {
	ID          int32          `json:"id"`
	Name        string         `json:"name"`
	Tenant      string         `json:"tenant"`
	IPs         []ipEntryJSON  `json:"ips"`
	BoundaryIFs []deviceIfJSON `json:"boundary_ifs"`
	PolicyID    int32          `json:"policy_id"`
}

type ipEntryJSON struct {
	Prefix string `json:"prefix"` // CIDR；单 IP 用 /32（v4）或 /128（v6）
}

type deviceIfJSON struct {
	DeviceID uint32 `json:"device_id"`
	IfIndex  uint32 `json:"if_index"`
}

// ipEntryFromCIDR —— CIDR → IPEntry（v4 → ::ffff:/96 映射 16B；网络位归一化）。
func ipEntryFromCIDR(cidr string) (IPEntry, error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return IPEntry{}, fmt.Errorf("parse prefix %q: %w", cidr, err)
	}
	p = p.Masked()
	a := p.Addr()
	var b [16]byte
	if a.Is4() {
		v4 := a.As4()
		b[10], b[11] = 0xff, 0xff
		copy(b[12:16], v4[:])
	} else {
		b = a.As16()
	}
	return IPEntry{Prefix: b, MaskLen: int32(p.Bits())}, nil
}
