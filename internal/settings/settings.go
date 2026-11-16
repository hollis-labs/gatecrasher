// Package settings parses operator configuration. Credentials remain in private
// external files; no identity, key, trust mapping or live grant is provisioned.
package settings

import (
	"bytes"
	"encoding/json"
	"fmt"
)

const Key = "gatecrasher"

type Settings struct {
	AllowedHosts      []string          `json:"allowed_hosts"`
	OwnerRef          string            `json:"owner_ref"`
	CallerScope       string            `json:"caller_scope"`
	CallbackSubject   string            `json:"callback_subject"`
	ActorMap          map[string]string `json:"actor_map"`
	TachyonURL        string            `json:"tachyon_url"`
	ProducerTokenFile string            `json:"producer_token_file"`
}

func Parse(raw any) (Settings, error) {
	var s Settings
	if raw == nil {
		return s, nil
	}
	if _, ok := raw.(map[string]any); !ok {
		return s, fmt.Errorf("gatecrasher: config block must be a map")
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return s, err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err = d.Decode(&s); err != nil {
		return s, fmt.Errorf("gatecrasher: invalid config: %w", err)
	}
	for _, host := range s.AllowedHosts {
		if host == "" || host == " " {
			return s, fmt.Errorf("gatecrasher: empty allowed host")
		}
	}
	return s, nil
}
