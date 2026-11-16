package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/hollis-labs/libs/mesh/core/gate"

	"github.com/hollis-labs/libs/agent/sdk"
	"github.com/hollis-labs/libs/llm/core/llmcontracts"
	"github.com/hollis-labs/libs/llm/core/llmtypes"
	"github.com/hollis-labs/libs/mesh/core/agentdef"
	"github.com/hollis-labs/libs/mesh/core/runtimecontract"
	libauth "github.com/hollis-labs/libs/security/auth"
)

const RecipeScope = "gatecrasher.recipe.run"

func strictJSON(raw []byte, out any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	d.UseNumber()
	if err := d.Decode(out); err != nil {
		return err
	}
	if err := d.Decode(new(any)); !errors.Is(err, io.EOF) {
		return ErrRefused
	}
	return nil
}
func digest(version, value string) runtimecontract.Digest {
	sum := sha256.Sum256([]byte(value))
	return runtimecontract.Digest{Scheme: "sha256", DescriptorVersion: version, Value: hex.EncodeToString(sum[:])}
}
func reference(owner runtimecontract.OwnerID, id string) runtimecontract.Reference {
	return runtimecontract.Reference{ID: id, Revision: "1", Digest: digest("", id), IssuerRef: "gatecrasher", OwnerID: owner}
}
func RecipeDefinition() agentdef.Definition {
	return agentdef.Definition{SchemaVersion: agentdef.SchemaVersion, DefinitionID: "gatecrasher-fingerprint", Revision: "1", Name: "gatecrasher-fingerprint", Description: "Approval-gated fingerprint of bounded text", Body: "Call fingerprint once with the supplied text, then report the returned digest. Do not call another tool.", Behavior: agentdef.Behavior{Purpose: "Bounded approval-gated fingerprint"}, Requirements: agentdef.Requirements{Tools: []string{"fingerprint"}, Requires: []string{sdk.CapabilityApproval}}, HarnessProfile: agentdef.HarnessProfile{Permissions: agentdef.PermissionProfile{Profile: PolicyID}}, Continuity: agentdef.Continuity{Mode: agentdef.Ephemeral}}
}
func RecipeDefinitionDigest() string {
	d := RecipeDefinition()
	sum, err := agentdef.Digest(&d)
	if err != nil {
		panic(err)
	}
	return sum
}
func FingerprintTool(owner runtimecontract.OwnerID) sdk.Tool {
	return sdk.Tool{Definition: llmtypes.ToolDefinition{Name: "fingerprint", Description: "Compute SHA-256 of text; no file, process or network effects", InputSchema: map[string]any{"type": "object", "properties": map[string]any{"text": map[string]any{"type": "string", "maxLength": 4096}}, "required": []string{"text"}, "additionalProperties": false}}, Versions: []runtimecontract.Reference{reference(owner, "tool:fingerprint:v1")}, Execute: func(ctx context.Context, args map[string]any) (sdk.ToolResult, error) {
		if ctx.Err() != nil {
			return sdk.ToolResult{}, context.Cause(ctx)
		}
		if len(args) != 1 {
			return sdk.ToolResult{}, ErrRefused
		}
		text, ok := args["text"].(string)
		if !ok || len(text) > 4096 {
			return sdk.ToolResult{}, ErrRefused
		}
		sum := sha256.Sum256([]byte(text))
		return sdk.ToolResult{Content: hex.EncodeToString(sum[:])}, nil
	}}
}

// Recipe composes the REAL SDK with production host ports. Router is an explicit
// host-owned model binding, not request input. There is no fake production model
// or arbitrary tool/launch selection. Tests may inject a deterministic provider.
func (s *Service) Recipe(input sdk.Input, router *sdk.Router) (*sdk.Operative, error) {
	if s.coordinator == nil || router == nil {
		return nil, ErrUnconfigured
	}
	return sdk.New(RecipeDefinition(), sdk.Ports{Router: router, Tools: []sdk.Tool{FingerprintTool(input.Binding.OwnerID)}, Environment: Environment{Host: s}, Admission: s, Policy: s, Authority: s, Gate: sdk.GateAdapter{Port: SDKGate{Host: s}, Wait: gate.WaitOptions{MaxWait: 30 * time.Second}}, Events: s, Now: s.cfg.Now, Capabilities: []string{sdk.CapabilityApproval, "tool.execute"}, Limits: sdk.Limits{MaxTurns: 3, ApprovalTTL: time.Minute}})
}

// RunRecipe is the single registered recipe service. Enrollment uses the
// authenticated host caller and explicit operator identity mapping. It issues
// local references for this pure tool, not workspace provisioning authority.
func (s *Service) RunRecipe(ctx context.Context, p libauth.Principal, id, text string, provider llmcontracts.Provider) (result sdk.Result, runErr error) {
	if provider == nil || s.coordinator == nil {
		return sdk.Result{}, ErrUnconfigured
	}
	if !p.Verified || p.Audience != "gatecrasher" || !p.HasScope(RecipeScope) || (!p.ExpiresAt.IsZero() && !s.cfg.Now().Before(p.ExpiresAt)) || id == "" || len(id) > 128 || len(text) > 4096 || strings.TrimSpace(text) == "" {
		return sdk.Result{}, ErrRefused
	}
	canonical := s.cfg.ActorMap["gatecrasher/"+p.ID]
	if canonical == "" {
		return sdk.Result{}, ErrRefused
	}
	facts, err := s.enrollRecipe(ctx, canonical, id)
	if err != nil {
		return sdk.Result{}, err
	}
	binding, env := facts.Binding, facts.Environment
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if cleanupErr := s.Revoke(cleanup, binding); cleanupErr != nil {
			runErr = errors.Join(runErr, ErrCleanup, cleanupErr)
			result.Status = sdk.Failed
		}
	}()
	router, err := sdk.NewRouter("host-model", sdk.Route{Name: "host-model", Model: "configured-host-model", Provider: provider})
	if err != nil {
		return sdk.Result{}, err
	}
	input := sdk.Input{ID: id, Binding: binding, Environment: env, Text: text}
	operative, err := s.Recipe(input, router)
	if err != nil {
		return sdk.Result{}, err
	}
	return operative.Run(ctx, input)
}

func (s *Service) enrollRecipe(ctx context.Context, canonical, runID string) (RuntimeFacts, error) {
	s.recipeMu.Lock()
	defer s.recipeMu.Unlock()
	owner := runtimecontract.OwnerID(canonical)
	// The configured canonical actor survives credential rotation. Attempts and
	// generations may advance; the logical run namespace never does on retry.
	conversation := digest("recipe-conversation-v1", canonical).Value
	binding := runtimecontract.Binding{OwnerID: owner, OperativeID: "gatecrasher-fingerprint", ConversationID: runtimecontract.ConversationID(conversation), Generation: 1}
	var reserved int
	if err := s.st.Reader().QueryRowContext(ctx, `SELECT 1 FROM run_reservations WHERE logical_key=?`, logicalKey(binding, runID)).Scan(&reserved); err == nil {
		return RuntimeFacts{}, sdk.ErrRunUsed
	} else if !isNoRows(err) {
		return RuntimeFacts{}, err
	}
	var old string
	var active int
	err := s.st.Reader().QueryRowContext(ctx, `SELECT facts_json,active FROM runtime_facts WHERE slot_key=?`, logicalKey(binding, "")).Scan(&old, &active)
	if err == nil {
		var prev RuntimeFacts
		if decode(old, &prev) != nil {
			return RuntimeFacts{}, ErrRefused
		}
		if active == 1 {
			return RuntimeFacts{}, sdk.ErrBusy
		}
		binding.Generation = prev.Binding.Generation + 1
	} else if !isNoRows(err) {
		return RuntimeFacts{}, err
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return RuntimeFacts{}, err
	}
	binding.AttemptID = runtimecontract.AttemptID(hex.EncodeToString(nonce[:]))
	expiry := s.cfg.Now().Add(2 * time.Minute)
	base := "recipe:" + string(binding.AttemptID)
	env := runtimecontract.EnvironmentRef{Receipt: reference(owner, base), Workspace: reference(owner, "workspace:pure-fingerprint"), Lease: reference(owner, base+":lease"), Grants: reference(owner, base+":grants"), Capabilities: []string{"tool.execute", sdk.CapabilityApproval}, ExpiresAt: expiry}
	facts := RuntimeFacts{Binding: binding, Environment: env, Requester: canonical, Resources: FingerprintTool(owner).Versions, Policy: reference(owner, PolicyID)}
	if err = s.Enroll(ctx, facts); err != nil {
		return RuntimeFacts{}, err
	}
	return facts, nil
}

// RecipeRunner is a closed recipe binding for an app transport. Provider is
// supplied by trusted composition, never decoded from an HTTP request.
type RecipeRunner struct {
	Host     *Service
	Provider llmcontracts.Provider
}

func (r RecipeRunner) Run(ctx context.Context, p libauth.Principal, id, text string) (sdk.Result, error) {
	if r.Host == nil {
		return sdk.Result{}, ErrUnconfigured
	}
	return r.Host.RunRecipe(ctx, p, id, text, r.Provider)
}
