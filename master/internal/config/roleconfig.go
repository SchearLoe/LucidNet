package config

import (
	"context"
	"encoding/json"
	"fmt"
)

// RoleConfig —— RegisterNode 返回的本节点角色配置（docs/dd/07 §1 "返回分配的角色配置"）。
// 组包口径：按节点角色取相关 etcd 作用域当前快照；数据本体仍以 etcd watch 为准，
// 此处为启动自举快照（组件启动早期 watch 尚未建立时的兜底）。
type RoleConfig struct {
	Scopes map[string]Envelope `json:"scopes"`
}

// RoleScopes —— 角色 → 相关配置作用域（docs/09 §5 消费方对照）。
func RoleScopes(role string, nodeID string) []string {
	switch role {
	case "collector":
		return []string{ScopeZones, CollectorScope(nodeID)}
	case "broker":
		return []string{ScopeForwardRules}
	case "analytics":
		return []string{ScopeAnalytics}
	default: // storage|master|bgp：暂无 per-role 配置作用域
		return nil
	}
}

// RoleConfigJSON 为节点组包角色配置（未知/缺失作用域静默跳过）。
func (s *Store) RoleConfigJSON(ctx context.Context, role, nodeID string) (string, error) {
	rc := RoleConfig{Scopes: map[string]Envelope{}}
	for _, scope := range RoleScopes(role, nodeID) {
		env, err := s.Current(ctx, scope)
		if err != nil {
			continue // 无历史版本：空配置启动
		}
		rc.Scopes[scope] = env
	}
	if role == "collector" {
		// 分配表指针（数据本体 /lucid/assign/flow，Broker/Collector watch）
		rc.Scopes["_assign_hint"] = Envelope{Data: json.RawMessage(
			fmt.Sprintf(`{"key":%q,"watch":true}`, ScopeAssignFlow))}
	}
	b, err := json.Marshal(rc)
	if err != nil {
		return "", fmt.Errorf("marshal role config for %s: %w", nodeID, err)
	}
	return string(b), nil
}
