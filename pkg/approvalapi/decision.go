package approvalapi

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// JWK is one Ed25519 public key in a JWKS (kty OKP, crv Ed25519).
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	Kid string `json:"kid"`
	X   string `json:"x"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
}

// JWKS is the body of GET /api/gate/v1/jwks.json.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// PublicJWK is the JWK of an Ed25519 public key.
func PublicJWK(kid string, pub ed25519.PublicKey) JWK {
	return JWK{Kty: "OKP", Crv: "Ed25519", Kid: kid, X: base64.RawURLEncoding.EncodeToString(pub), Use: "sig", Alg: "EdDSA"}
}

// Key returns the Ed25519 key with this kid.
func (s JWKS) Key(kid string) (ed25519.PublicKey, error) {
	for _, k := range s.Keys {
		if k.Kid != kid {
			continue
		}
		if k.Kty != "OKP" || k.Crv != "Ed25519" {
			return nil, fmt.Errorf("decision: key %q is not Ed25519", kid)
		}
		if k.Alg != "" && k.Alg != "EdDSA" {
			return nil, fmt.Errorf("decision: key %q is for %s", kid, k.Alg)
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("decision: key %q is malformed", kid)
		}
		return ed25519.PublicKey(x), nil
	}
	return nil, fmt.Errorf("decision: no key %q", kid)
}

type jwsHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ,omitempty"`
}

// DecisionType is the typ header of a decision.
const DecisionType = "gatecrasher-decision+jwt"

// SignDecision signs claims as a compact JWS (EdDSA). The server uses it; producers can
// use it to build fakes.
func SignDecision(key ed25519.PrivateKey, kid string, c DecisionClaims) (string, error) {
	h, err := json.Marshal(jwsHeader{Alg: "EdDSA", Kid: kid, Typ: DecisionType})
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	input := enc.EncodeToString(h) + "." + enc.EncodeToString(p)
	return input + "." + enc.EncodeToString(ed25519.Sign(key, []byte(input))), nil
}

// Errors from VerifyDecision and Check.
var (
	ErrMalformed = errors.New("decision: malformed")
	ErrSignature = errors.New("decision: bad signature")
	ErrExpired   = errors.New("decision: expired")
	ErrMismatch  = errors.New("decision: does not match the request")
)

// VerifyDecision checks a decision's signature against keys, its issuer, its audience
// and its lifetime at now, and returns its claims. It does not tie the decision to a
// request: call Check for that.
func VerifyDecision(token string, keys JWKS, audience string, now time.Time) (DecisionClaims, error) {
	var c DecisionClaims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return c, ErrMalformed
	}
	enc := base64.RawURLEncoding
	hb, err := enc.DecodeString(parts[0])
	if err != nil {
		return c, ErrMalformed
	}
	var h jwsHeader
	if err = json.Unmarshal(hb, &h); err != nil {
		return c, ErrMalformed
	}
	var hm map[string]json.RawMessage
	if err = json.Unmarshal(hb, &hm); err != nil {
		return c, ErrMalformed
	}
	if _, ok := hm["crit"]; ok {
		// No critical header extensions are understood (RFC 7515 section 4.1.11).
		return c, fmt.Errorf("%w: crit", ErrMalformed)
	}
	if h.Alg != "EdDSA" || h.Kid == "" {
		return c, fmt.Errorf("%w: alg %q", ErrMalformed, h.Alg)
	}
	if h.Typ != "" && h.Typ != DecisionType {
		return c, fmt.Errorf("%w: typ %q", ErrMalformed, h.Typ)
	}
	pub, err := keys.Key(h.Kid)
	if err != nil {
		return c, err
	}
	sig, err := enc.DecodeString(parts[2])
	if err != nil {
		return c, ErrMalformed
	}
	if !ed25519.Verify(pub, []byte(parts[0]+"."+parts[1]), sig) {
		return c, ErrSignature
	}
	pb, err := enc.DecodeString(parts[1])
	if err != nil {
		return c, ErrMalformed
	}
	// Unknown claims are ignored, so the issuer can add claims without breaking verifiers.
	if err := json.Unmarshal(pb, &c); err != nil {
		return c, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	switch {
	case c.Iss != Issuer:
		return c, fmt.Errorf("%w: iss %q", ErrMismatch, c.Iss)
	case c.Aud != audience:
		return c, fmt.Errorf("%w: aud %q", ErrMismatch, c.Aud)
	case c.Exp <= c.Iat || time.Duration(c.Exp-c.Iat)*time.Second > MaxDecisionLifetime:
		return c, fmt.Errorf("%w: lifetime", ErrMalformed)
	case now.Unix() >= c.Exp:
		return c, ErrExpired
	case c.Outcome != OutcomeApproved && c.Outcome != OutcomeDenied:
		return c, fmt.Errorf("%w: outcome %q", ErrMalformed, c.Outcome)
	}
	return c, nil
}

// Expect is what a producer asked for, to check a decision against.
type Expect struct {
	RequestID     string    // the idempotency_key submitted
	RequestDigest string    // the digest submitted
	Tier          Tier      // the tier submitted
	Requested     Requested // to check that a narrowing only narrows
	// Owner is the owner's principal id; a critical decision must be decided by it,
	// as a human.
	Owner string
	// SecretRequest is set when the request was a secret_request. Its approval is
	// decided by the producer itself (decider kind app, sub equal to aud), carrying the
	// secret reference: the producer's own intake received the value. A decline is
	// still the owner's.
	SecretRequest bool
}

// Check ties verified claims to the request: request id, digest and tier must match;
// a critical decision must come from the owner as a human; a narrowing may only drop
// scopes or shorten the TTL.
func (c DecisionClaims) Check(e Expect) error {
	switch {
	case c.RequestID != e.RequestID:
		return fmt.Errorf("%w: request_id", ErrMismatch)
	case c.RequestDigest != e.RequestDigest:
		return fmt.Errorf("%w: request_digest", ErrMismatch)
	case c.Tier != e.Tier:
		return fmt.Errorf("%w: tier", ErrMismatch)
	}
	byProducer := e.SecretRequest && c.Outcome == OutcomeApproved && c.Decider.Kind == KindApp && c.Decider.Sub == c.Aud && c.Response != nil && c.Response.SecretRef != ""
	if c.Tier == TierCritical && !byProducer && (c.Decider.Kind != KindHuman || e.Owner == "" || c.Decider.Sub != e.Owner) {
		return fmt.Errorf("%w: a critical decision needs the owner", ErrMismatch)
	}
	if n := c.Narrowed; n != nil {
		for _, s := range n.Scopes {
			if !slices.Contains(e.Requested.Scopes, s) {
				return fmt.Errorf("%w: narrowed scope %q was not requested", ErrMismatch, s)
			}
		}
		if n.TTLSeconds < 0 || n.TTLSeconds > e.Requested.TTLSeconds {
			return fmt.Errorf("%w: narrowed ttl", ErrMismatch)
		}
	}
	return nil
}
