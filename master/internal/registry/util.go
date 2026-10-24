package registry

import (
	"encoding/json"
	"fmt"
)

func errf(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}

// ProfileJSON —— /lucid/nodes/{id} 节点档案 JSON（docs/hld/07 §3）。
func ProfileJSON(n Node) ([]byte, error) {
	b, err := json.Marshal(struct {
		ID       string  `json:"id"`
		Role     string  `json:"role"`
		Host     string  `json:"host"`
		Cores    uint32  `json:"cores"`
		MemGB    uint32  `json:"mem_gb"`
		NICs     []NIC   `json:"nics"`
		State    string  `json:"state"`
		Version  string  `json:"version"`
		Weight   float64 `json:"weight"`
		JoinedAt string  `json:"joined_at,omitempty"`
	}{
		ID: n.ID, Role: string(n.Role), Host: n.Host,
		Cores: n.Cores, MemGB: n.MemGB, NICs: n.NICs,
		State: string(n.State), Version: n.Version, Weight: n.Weight(),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal node profile %s: %w", n.ID, err)
	}
	return b, nil
}
