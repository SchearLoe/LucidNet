package rbac

import (
	"encoding/json"
	"fmt"
)

func jsonMarshal(v []string) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func jsonUnmarshalStrings(b []byte) ([]string, error) {
	var out []string
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("decode json string array: %w", err)
	}
	return out, nil
}
