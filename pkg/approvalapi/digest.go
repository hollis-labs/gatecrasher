package approvalapi

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// digestInput is the object the request digest covers.
type digestInput struct {
	Principal Principal `json:"principal"`
	Requested Requested `json:"requested"`
	Tier      Tier      `json:"tier"`
}

// RequestDigest is "sha256:" and the lowercase hex SHA-256 of the RFC 8785 canonical
// JSON of {"principal":…, "requested":…, "tier":…}, encoded as the types in this
// package encode them: act is omitted when empty, constraints is always an object
// (nil becomes {}), and scopes is always an array (nil becomes []).
func RequestDigest(p Principal, r Requested, t Tier) (string, error) {
	if r.Constraints == nil {
		r.Constraints = map[string]any{}
	}
	if r.Scopes == nil {
		r.Scopes = []string{}
	}
	raw, err := json.Marshal(digestInput{Principal: p, Requested: r, Tier: t})
	if err != nil {
		return "", fmt.Errorf("request digest: %w", err)
	}
	canon, err := Canonicalize(raw)
	if err != nil {
		return "", fmt.Errorf("request digest: %w", err)
	}
	sum := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// Digest computes the request digest of a submit from its own fields.
func (s SubmitRequest) Digest() (string, error) {
	return RequestDigest(s.Principal, s.Requested, s.Tier)
}
