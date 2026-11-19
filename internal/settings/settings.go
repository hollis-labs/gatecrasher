// Package settings parses operator configuration. Credentials remain in private
// external files; no identity, key, trust mapping or live grant is provisioned.
package settings

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
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
	Approvals         Approvals         `json:"approvals"`
}

// Approvals configures the approval inbox (gate v1). With no owner and no producers
// configured the approval routes refuse every call.
type Approvals struct {
	// Owner is the single human who decides critical requests (and may decide any).
	Owner Owner `json:"owner"`
	// Producers maps a Gatecrasher principal id (for an identity key, "key:<id>") to the
	// source name it submits as; that name is also the aud of its decisions.
	Producers map[string]string `json:"producers"`
	// Classes are the approver classes elevated requests may name ("approve.<class>").
	Classes map[string]Class `json:"classes"`
	// DecisionKeyFile holds the Ed25519 decision signing key, created 0600 on first
	// start. Relative paths are resolved next to the database.
	DecisionKeyFile string `json:"decision_key_file"`
}

// Owner binds the owner's Gatecrasher identity to the registry id decisions carry.
type Owner struct {
	Principal string `json:"principal"` // the owner's Gatecrasher principal id (an operator)
	Sub       string `json:"sub"`       // the registry id put in decider.sub
}

// Class is one approver class: the agents that may decide it, how far they may go, and
// whether their decisions only shadow the owner's.
type Class struct {
	// Agents maps a Gatecrasher principal id to the agent's registry id. The caller
	// must also hold the class itself as a scope.
	Agents  map[string]string `json:"agents"`
	Ceiling Ceiling           `json:"ceiling"`
	// Shadow records an agent's decision without acting on it; the request stays
	// pending for the owner.
	Shadow bool `json:"shadow"`
}

// Ceiling bounds what an approver agent may approve in a class. Empty lists and a zero
// TTL mean no approvals by agents at all: a ceiling must be stated to be granted.
type Ceiling struct {
	MaxTTLSeconds int64    `json:"max_ttl_seconds"`
	Audiences     []string `json:"audiences"`
	Scopes        []string `json:"scopes"`
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
	if err = s.Approvals.validate(); err != nil {
		return s, err
	}
	return s, nil
}

func (a Approvals) validate() error {
	if (a.Owner.Principal == "") != (a.Owner.Sub == "") {
		return fmt.Errorf("gatecrasher: approvals.owner needs both principal and sub")
	}
	for id, src := range a.Producers {
		if id == "" || src == "" {
			return fmt.Errorf("gatecrasher: empty approvals producer")
		}
	}
	for name, c := range a.Classes {
		if !strings.HasPrefix(name, "approve.") || len(name) == len("approve.") {
			return fmt.Errorf("gatecrasher: approver class %q must be approve.<class>", name)
		}
		for id, sub := range c.Agents {
			if id == "" || sub == "" {
				return fmt.Errorf("gatecrasher: empty approver in %s", name)
			}
		}
		if c.Ceiling.MaxTTLSeconds < 0 {
			return fmt.Errorf("gatecrasher: negative ceiling in %s", name)
		}
	}
	return nil
}
