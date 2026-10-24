package config

import (
	"fmt"
	"net/netip"
	"strings"
)

// 配置业务校验（docs/dd/07 §5：Master 校验 schema + 业务规则后才能发布）。
//
//   - /lucid/zones：R2 —— zone IP 重叠拒绝（docs/dd/02 §3：一条 IP 同属多 zone 禁止，
//     冲突返回错误）；zone_match 仅 dst|src（09 §3 裁定：禁止 both）。
//   - /lucid/forward/rules：R1 —— passthrough 目的地带 resample 直接拒绝
//     （docs/dd/01 §3.2-3）。
//   - 其余作用域：JSON 结构校验（对象），schema 注册表 TODO(M2)。

type zoneBind struct {
	zone   *ZoneSpec
	prefix netip.Prefix
}

// ValidateZones —— Zone 快照校验（R2）。
func ValidateZones(data []byte) error {
	zones, err := parseZones(data)
	if err != nil {
		return err
	}
	if len(zones) == 0 {
		return fmt.Errorf("zones snapshot must not be empty")
	}
	ids := map[int64]string{}  // id → name
	names := map[string]bool{} // name → exists
	var v4, v6 []zoneBind
	for i := range zones {
		z := &zones[i]
		if z.ID <= 0 {
			return fmt.Errorf("zone[%d]: id must be positive", i)
		}
		if z.Name == "" {
			return fmt.Errorf("zone %d: name required", z.ID)
		}
		if other, dup := ids[int64(z.ID)]; dup {
			return fmt.Errorf("zone id %d duplicated (%s / %s)", z.ID, other, z.Name)
		}
		if names[z.Name] {
			return fmt.Errorf("zone name %q duplicated", z.Name)
		}
		if z.Tenant == "" {
			return fmt.Errorf("zone %d: tenant required", z.ID)
		}
		switch strings.ToLower(z.ZoneMatch) {
		case "", "dst", "src": // 默认 dst；禁止 both（docs/09 §3）
		default:
			return fmt.Errorf("zone %d: zone_match %q invalid (dst|src only, both forbidden)", z.ID, z.ZoneMatch)
		}
		if len(z.IPs) == 0 {
			return fmt.Errorf("zone %d: at least one ip entry required", z.ID)
		}
		ids[int64(z.ID)] = z.Name
		names[z.Name] = true
		for ii, ip := range z.IPs {
			p, err := netip.ParsePrefix(ip.Prefix)
			if err != nil {
				return fmt.Errorf("zone %d ip[%d]: parse prefix %q: %w", z.ID, ii, ip.Prefix, err)
			}
			p = p.Masked()
			z.IPs[ii].Prefix = p.String()
			if p.Addr().Is4() || p.Addr().Is4In6() {
				v4 = append(v4, zoneBind{z, netip.PrefixFrom(p.Addr().Unmap(), p.Bits())})
			} else {
				v6 = append(v6, zoneBind{z, p})
			}
		}
	}
	// R2 重叠检测：按族两两比对（规模：单客户 ≤1000 IP、集群 ≤300 客户起步）
	if err := overlapCheck(v4); err != nil {
		return err
	}
	return overlapCheck(v6)
}

func overlapCheck(binds []zoneBind) error {
	for a := 0; a < len(binds); a++ {
		for b := a + 1; b < len(binds); b++ {
			if binds[a].prefix.Overlaps(binds[b].prefix) {
				za, zb := binds[a].zone, binds[b].zone
				return fmt.Errorf("R2 overlap: zone %d(%s) %s overlaps zone %d(%s) %s",
					za.ID, za.Name, binds[a].prefix, zb.ID, zb.Name, binds[b].prefix)
			}
		}
	}
	return nil
}

// ValidateForwardRules —— 转发规则快照校验（R1）。
func ValidateForwardRules(data []byte) error {
	rules, err := parseForwardRules(data)
	if err != nil {
		return err
	}
	ids := map[int64]bool{}
	for i := range rules {
		r := &rules[i]
		if r.ID <= 0 {
			return fmt.Errorf("rule[%d]: id must be positive", i)
		}
		if ids[r.ID] {
			return fmt.Errorf("rule id %d duplicated", r.ID)
		}
		ids[r.ID] = true
		if r.Name == "" {
			return fmt.Errorf("rule %d: name required", r.ID)
		}
		if len(r.Match.Exporters) == 0 && len(r.Match.ExporterGroups) == 0 {
			return fmt.Errorf("rule %d: match requires exporters or exporter_groups", r.ID)
		}
		if len(r.Match.Exporters) > 10000 {
			return fmt.Errorf("rule %d: exporters over 10000 limit (docs/dd/01 §3.2-2)", r.ID)
		}
		for _, e := range r.Match.Exporters {
			addr, err := netip.ParseAddr(e)
			if err != nil {
				return fmt.Errorf("rule %d: exporter %q is not a valid ip: %w", r.ID, e, err)
			}
			_ = addr
		}
		// exporter_groups 展开上限（dd/01 §3.2-2 ≤10000）需组台账，表 M2 落地，先结构校验
		if len(r.Destinations) == 0 {
			return fmt.Errorf("rule %d: at least one destination required", r.ID)
		}
		for di, d := range r.Destinations {
			if d.Addr == "" || !strings.Contains(d.Addr, ":") {
				return fmt.Errorf("rule %d dest[%d]: addr must be host:port", r.ID, di)
			}
			switch d.Protocol {
			case "passthrough":
				// R1 裁定：passthrough 不支持 resample（无法在原始报文内安全抽稀）
				if d.Resample != nil {
					return fmt.Errorf("rule %d dest[%d]: passthrough does not support resample (R1)", r.ID, di)
				}
			case "netflow5", "ipfix":
				if d.Resample != nil {
					switch d.Resample.Mode {
					case "deterministic", "random":
					default:
						return fmt.Errorf("rule %d dest[%d]: resample mode %q invalid", r.ID, di, d.Resample.Mode)
					}
					if d.Resample.Rate < 1 {
						return fmt.Errorf("rule %d dest[%d]: resample rate must be >= 1", r.ID, di)
					}
				}
			default:
				return fmt.Errorf("rule %d dest[%d]: protocol %q invalid (passthrough|netflow5|ipfix)", r.ID, di, d.Protocol)
			}
		}
	}
	return nil
}

// ValidateJSONDoc —— 通用 JSON 对象校验（/lucid/config/analytics 与
// /lucid/config/collector/{node}；schema 注册表见 TODO）。
func ValidateJSONDoc(data []byte) error {
	var v map[string]any
	if err := jsonUnmarshal(data, &v); err != nil {
		return fmt.Errorf("config snapshot must be a json object: %w", err)
	}
	return nil
}

func parseZones(data []byte) ([]ZoneSpec, error) {
	arr, err := parseSnapshot(data)
	if err != nil {
		return nil, err
	}
	out := make([]ZoneSpec, 0, len(arr))
	for i, raw := range arr {
		var z ZoneSpec
		if err := jsonUnmarshal(raw, &z); err != nil {
			return nil, fmt.Errorf("zone[%d]: %w", i, err)
		}
		out = append(out, z)
	}
	return out, nil
}

func parseForwardRules(data []byte) ([]ForwardRule, error) {
	arr, err := parseSnapshot(data)
	if err != nil {
		return nil, err
	}
	out := make([]ForwardRule, 0, len(arr))
	for i, raw := range arr {
		var r ForwardRule
		if err := jsonUnmarshal(raw, &r); err != nil {
			return nil, fmt.Errorf("rule[%d]: %w", i, err)
		}
		out = append(out, r)
	}
	return out, nil
}
