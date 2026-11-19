// Package settings parses operator configuration. Credentials remain in private
// external files; no identity, key, trust mapping or live grant is provisioned.
package settings

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
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
	Auth              Auth              `json:"auth"`
}

// Trust modes.
const (
	TrustStandalone = "standalone"
	TrustWarden     = "warden"
)

// Auth chooses whose credentials Gatecrasher accepts besides its own identity keys.
// Standalone (the default) trusts only its own. Warden also accepts Warden-issued
// EdDSA JWTs with aud=gatecrasher, verified against Warden's JWKS.
type Auth struct {
	Trust  string `json:"trust"`
	Warden Warden `json:"warden"`
}

// Warden is how to verify Warden-issued tokens.
type Warden struct {
	Issuer           string `json:"issuer"`
	JWKSURL          string `json:"jwks_url"`
	BootstrapKeyFile string `json:"bootstrap_key_file"`
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
	// IntakeOrigins maps a producer source to the origins (scheme://host[:port]) its
	// secret_request intake URLs may use. A source with none cannot request secrets.
	IntakeOrigins map[string][]string `json:"intake_origins"`
	// Webhooks are signed event deliveries to subscribers (surfaces).
	Webhooks []Webhook `json:"webhooks"`
}

// Webhook is one subscriber. View is what it may see: "owner" (everything) or an
// approver class ("approve.<class>": that class's elevated requests). SecretFile holds
// the HMAC key (at least 32 bytes, not readable by group or others).
type Webhook struct {
	Name       string `json:"name"`
	URL        string `json:"url"`
	SecretFile string `json:"secret_file"`
	View       string `json:"view"`
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
	if err = s.Auth.validate(); err != nil {
		return s, err
	}
	return s, nil
}

// TachyonConfigured reports whether any of the Tachyon response binding is configured;
// without it Gatecrasher serves approvals only.
func (s Settings) TachyonConfigured() bool {
	return s.OwnerRef != "" || s.CallerScope != "" || s.CallbackSubject != "" || s.TachyonURL != "" || s.ProducerTokenFile != "" || len(s.ActorMap) > 0
}

// ApprovalsConfigured reports whether the approval inbox has an owner.
func (s Settings) ApprovalsConfigured() bool { return s.Approvals.Owner.Principal != "" }

func (a Auth) validate() error {
	switch a.Trust {
	case "", TrustStandalone:
		return nil
	case TrustWarden:
		if a.Warden.Issuer == "" {
			return fmt.Errorf("gatecrasher: auth.warden.issuer is required for trust warden")
		}
		if a.Warden.JWKSURL == "" && a.Warden.BootstrapKeyFile == "" {
			return fmt.Errorf("gatecrasher: auth.warden needs jwks_url or bootstrap_key_file")
		}
		if a.Warden.JWKSURL != "" && !SafeURL(a.Warden.JWKSURL) {
			return fmt.Errorf("gatecrasher: auth.warden.jwks_url must be https (or http on loopback)")
		}
		return nil
	}
	return fmt.Errorf("gatecrasher: auth.trust must be standalone or warden")
}

// SafeURL reports whether raw is https, or http to a loopback host, with no user info.
func SafeURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return false
	}
	switch u.Scheme {
	case "https":
		return true
	case "http":
		h := u.Hostname()
		if h == "localhost" {
			return true
		}
		ip := net.ParseIP(h)
		return ip != nil && ip.IsLoopback()
	}
	return false
}

// Origin is a URL's scheme://host[:port], lower-cased, or "" when it has none.
func Origin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

func (a Approvals) validate() error {
	if (a.Owner.Principal == "") != (a.Owner.Sub == "") {
		return fmt.Errorf("gatecrasher: approvals.owner needs both principal and sub")
	}
	if strings.HasPrefix(a.Owner.Principal, "warden:") {
		return fmt.Errorf("gatecrasher: approvals.owner.principal must be a Gatecrasher identity, not a Warden one")
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
	for src, origins := range a.IntakeOrigins {
		for _, o := range origins {
			if src == "" || !SafeURL(o) || Origin(o) != strings.ToLower(strings.TrimSuffix(o, "/")) {
				return fmt.Errorf("gatecrasher: intake origin %q for %q must be scheme://host[:port], https or loopback http", o, src)
			}
		}
	}
	seen := map[string]bool{}
	for _, w := range a.Webhooks {
		switch {
		case w.Name == "" || seen[w.Name]:
			return fmt.Errorf("gatecrasher: webhook names must be set and unique")
		case !SafeURL(w.URL):
			return fmt.Errorf("gatecrasher: webhook %s url must be https (or http on loopback)", w.Name)
		case w.SecretFile == "":
			return fmt.Errorf("gatecrasher: webhook %s needs secret_file", w.Name)
		case w.View != "owner":
			if _, ok := a.Classes[w.View]; !ok {
				return fmt.Errorf("gatecrasher: webhook %s view must be owner or a configured approver class", w.Name)
			}
		}
		seen[w.Name] = true
	}
	return nil
}
