package entitlement

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestUpgradeExecutionCanonicalDualSignatureRoundTrip(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	controlPublic, controlPrivate := upgradeGrantTestKey(0x81)
	edgePublic, edgePrivate := upgradeGrantTestKey(0x82)
	execution := validUpgradeExecution(now)

	signed, err := SignUpgradeExecution(context.Background(), execution,
		testSigner{id: "control-execution-1", private: controlPrivate},
		testSigner{id: "edge-consumption-1", private: edgePrivate})
	if err != nil {
		t.Fatalf("SignUpgradeExecution() error = %v", err)
	}
	repeated, err := SignUpgradeExecution(context.Background(), execution,
		testSigner{id: "control-execution-1", private: controlPrivate},
		testSigner{id: "edge-consumption-1", private: edgePrivate})
	if err != nil || !reflect.DeepEqual(repeated, signed) {
		t.Fatalf("repeated signature = (%#v, %v), want %#v", repeated, err, signed)
	}
	encoded, err := signed.Encode()
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	wireDigest := sha256.Sum256(encoded)
	if got := hex.EncodeToString(wireDigest[:]); got != "a62308a0314e79384870a1d4729818fcd2fb488b1671c764a7f10ee15fe0166f" {
		t.Fatalf("canonical envelope sha256 = %s", got)
	}
	decoded, err := DecodeUpgradeExecution(encoded)
	if err != nil {
		t.Fatalf("DecodeUpgradeExecution() error = %v", err)
	}
	reencoded, err := decoded.Encode()
	if err != nil || !bytes.Equal(reencoded, encoded) {
		t.Fatalf("canonical roundtrip = (%q, %v), want %q", reencoded, err, encoded)
	}

	controlKeys := NewKeyRing()
	edgeKeys := NewKeyRing()
	_ = controlKeys.Add("control-execution-1", controlPublic)
	_ = edgeKeys.Add("edge-consumption-1", edgePublic)
	verified, err := VerifyUpgradeExecution(decoded, controlKeys, edgeKeys, executionVerifyOptions(now, execution))
	if err != nil || !reflect.DeepEqual(verified, execution) {
		t.Fatalf("VerifyUpgradeExecution() = (%#v, %v), want %#v", verified, err, execution)
	}

	controlSignature, _ := base64.RawURLEncoding.DecodeString(signed.ControlSignature)
	edgeSignature, _ := base64.RawURLEncoding.DecodeString(signed.EdgeSignature)
	if bytes.Equal(controlSignature, edgeSignature) {
		t.Fatal("control and edge domains produced the same signature")
	}
}

func TestUpgradeExecutionStrictDecodeAndValidation(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	_, controlPrivate := upgradeGrantTestKey(0x63)
	_, edgePrivate := upgradeGrantTestKey(0x64)
	signed, _ := SignUpgradeExecution(context.Background(), validUpgradeExecution(now),
		testSigner{id: "control-execution-1", private: controlPrivate},
		testSigner{id: "edge-consumption-1", private: edgePrivate})
	encoded, _ := signed.Encode()

	var object map[string]any
	_ = json.Unmarshal(encoded, &object)
	object["unknown"] = true
	unknown, _ := json.Marshal(object)
	object["execution"] = nil
	nullExecution, _ := json.Marshal(object)
	duplicate := bytes.Replace(encoded, []byte(`{"control_algorithm":`),
		[]byte(`{"control_algorithm":"Ed25519","control_algorithm":`), 1)
	for name, candidate := range map[string][]byte{
		"empty":              nil,
		"leading whitespace": append([]byte(" "), encoded...),
		"trailing value":     append(append([]byte(nil), encoded...), []byte("{}")...),
		"unknown field":      unknown,
		"null execution":     nullExecution,
		"duplicate field":    duplicate,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeUpgradeExecution(candidate); !errors.Is(err, ErrInvalidUpgradeExecutionEnvelope) {
				t.Fatalf("DecodeUpgradeExecution() error = %v", err)
			}
		})
	}

	base := validUpgradeExecution(now)
	for _, test := range []struct {
		name   string
		mutate func(*UpgradeExecution)
	}{
		{name: "unknown schema", mutate: func(value *UpgradeExecution) { value.Schema = "cdnca.upgrade.execution/v2" }},
		{name: "unknown action", mutate: func(value *UpgradeExecution) { value.Action = "download" }},
		{name: "noncanonical node", mutate: func(value *UpgradeExecution) { value.NodeID = "{00000000-0000-4000-8000-000000000021}" }},
		{name: "noncanonical current version", mutate: func(value *UpgradeExecution) { value.CurrentVersion = "v1.0.0" }},
		{name: "wrong operation", mutate: func(value *UpgradeExecution) { value.Operation = ReinstallOperation }},
		{name: "noncanonical grant digest", mutate: func(value *UpgradeExecution) { value.GrantDigest += "=" }},
		{name: "noncanonical artifact digest", mutate: func(value *UpgradeExecution) { value.SHA256Digest += "=" }},
		{name: "zero artifact size", mutate: func(value *UpgradeExecution) { value.ArtifactSizeBytes = 0 }},
		{name: "invalid URL", mutate: func(value *UpgradeExecution) { value.DownloadURL = "http://cdn.example/release" }},
		{name: "invalid window", mutate: func(value *UpgradeExecution) { value.NotBefore = value.IssuedAt - 1 }},
		{name: "window past grant", mutate: func(value *UpgradeExecution) { value.ExpiresAt = value.GrantExpiresAt + 1 }},
		{name: "zero revision", mutate: func(value *UpgradeExecution) { value.ReleaseSequence = 0 }},
		{name: "invalid rollout", mutate: func(value *UpgradeExecution) { value.Rollout.Percentage = 0 }},
		{name: "unsafe rollback", mutate: func(value *UpgradeExecution) { value.Rollback.Automatic = false }},
		{name: "null health command", mutate: func(value *UpgradeExecution) { value.Health.Command = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := base
			test.mutate(&candidate)
			if err := candidate.Validate(); !errors.Is(err, ErrInvalidUpgradeExecution) {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func TestUpgradeExecutionVerificationFailsClosed(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	controlPublic, controlPrivate := upgradeGrantTestKey(0x65)
	edgePublic, edgePrivate := upgradeGrantTestKey(0x66)
	execution := validUpgradeExecution(now)
	signed, _ := SignUpgradeExecution(context.Background(), execution,
		testSigner{id: "control-execution-1", private: controlPrivate},
		testSigner{id: "edge-consumption-1", private: edgePrivate})
	controlKeys := NewKeyRing()
	edgeKeys := NewKeyRing()
	_ = controlKeys.Add("control-execution-1", controlPublic)
	_ = edgeKeys.Add("edge-consumption-1", edgePublic)
	base := executionVerifyOptions(now, execution)

	cases := []struct {
		name    string
		signed  SignedUpgradeExecution
		control *KeyRing
		edge    *KeyRing
		options UpgradeExecutionVerifyOptions
		want    error
	}{
		{name: "unknown control key", signed: signed, edge: edgeKeys, options: base, want: ErrUnknownUpgradeExecutionControlKey},
		{name: "unknown edge key", signed: signed, control: controlKeys, options: base, want: ErrUnknownUpgradeExecutionEdgeKey},
	}
	for _, mismatch := range []struct {
		name string
		set  func(*UpgradeExecutionVerifyOptions)
	}{
		{name: "installation", set: func(value *UpgradeExecutionVerifyOptions) {
			value.ExpectedInstallationID = "00000000-0000-4000-8000-000000000099"
		}},
		{name: "node", set: func(value *UpgradeExecutionVerifyOptions) {
			value.ExpectedNodeID = "00000000-0000-4000-8000-000000000099"
		}},
		{name: "command", set: func(value *UpgradeExecutionVerifyOptions) {
			value.ExpectedCommandID = "00000000-0000-4000-8000-000000000099"
		}},
		{name: "nonce", set: func(value *UpgradeExecutionVerifyOptions) {
			value.ExpectedNonce = "00000000-0000-4000-8000-000000000099"
		}},
		{name: "current", set: func(value *UpgradeExecutionVerifyOptions) { value.ExpectedCurrentVersion = "1.0.1" }},
		{name: "target", set: func(value *UpgradeExecutionVerifyOptions) { value.ExpectedTargetVersion = "2.0.1" }},
	} {
		options := base
		mismatch.set(&options)
		cases = append(cases, struct {
			name    string
			signed  SignedUpgradeExecution
			control *KeyRing
			edge    *KeyRing
			options UpgradeExecutionVerifyOptions
			want    error
		}{name: mismatch.name + " mismatch", signed: signed, control: controlKeys, edge: edgeKeys,
			options: options, want: ErrUpgradeExecutionTargetMismatch})
	}
	notYetValid := base
	notYetValid.Now = time.Unix(execution.NotBefore, 0).Add(-VerifierClockSkew - time.Second)
	expired := base
	expired.Now = time.Unix(execution.ExpiresAt, 0)
	cases = append(cases,
		struct {
			name    string
			signed  SignedUpgradeExecution
			control *KeyRing
			edge    *KeyRing
			options UpgradeExecutionVerifyOptions
			want    error
		}{"not yet valid", signed, controlKeys, edgeKeys, notYetValid, ErrUpgradeExecutionNotYetValid},
		struct {
			name    string
			signed  SignedUpgradeExecution
			control *KeyRing
			edge    *KeyRing
			options UpgradeExecutionVerifyOptions
			want    error
		}{"expired", signed, controlKeys, edgeKeys, expired, ErrUpgradeExecutionExpired},
	)

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := VerifyUpgradeExecution(test.signed, test.control, test.edge, test.options); !errors.Is(err, test.want) {
				t.Fatalf("VerifyUpgradeExecution() error = %v, want %v", err, test.want)
			}
		})
	}

	tamperedControl := signed
	tamperedControl.Execution.ArtifactSizeBytes++
	if _, err := VerifyUpgradeExecution(tamperedControl, controlKeys, edgeKeys, base); !errors.Is(err, ErrInvalidUpgradeExecutionControlSignature) {
		t.Fatalf("control tamper error = %v", err)
	}
	tamperedEdge := signed
	tamperedEdge.EdgeSignature = signed.ControlSignature
	if _, err := VerifyUpgradeExecution(tamperedEdge, controlKeys, edgeKeys, base); !errors.Is(err, ErrInvalidUpgradeExecutionEdgeSignature) {
		t.Fatalf("edge domain swap error = %v", err)
	}
}

func TestCanonicalUpgradeGrantDigestUsesExactCanonicalSignedWire(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	_, privateKey := upgradeGrantTestKey(0x67)
	manifest := validArtifactManifest()
	artifactSignature, _ := SignArtifactManifest(context.Background(), manifest,
		testSigner{id: "release-key-1", private: privateKey})
	grant := validUpgradeGrant(now, artifactSignature)
	grant.ArtifactSignatureKeyID = "release-key-1"
	signed, _ := SignUpgradeGrant(context.Background(), grant,
		testSigner{id: "release-key-1", private: privateKey})
	encoded, _ := signed.Encode()

	digest, err := CanonicalUpgradeGrantDigest(encoded)
	if err != nil {
		t.Fatalf("CanonicalUpgradeGrantDigest() error = %v", err)
	}
	want := sha256.Sum256(encoded)
	if digest != base64.RawURLEncoding.EncodeToString(want[:]) {
		t.Fatalf("digest = %q, want %q", digest, base64.RawURLEncoding.EncodeToString(want[:]))
	}
	if _, err := CanonicalUpgradeGrantDigest(append([]byte(" "), encoded...)); !errors.Is(err, ErrInvalidUpgradeGrantEnvelope) {
		t.Fatalf("noncanonical digest error = %v", err)
	}
}

func TestIssueCommandExecutionDerivesEveryFrozenGrantField(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	commandPublic, commandPrivate := upgradeGrantTestKey(0x91)
	controlPublic, controlPrivate := upgradeGrantTestKey(0x92)
	edgePublic, edgePrivate := upgradeGrantTestKey(0x93)
	grant := validUpgradeCommandGrantV2(t, now, commandPrivate)
	grant.ArtifactSignatureKeyID = "release-command-key"
	artifactManifest := ArtifactManifestV2{
		Schema: ArtifactManifestV2Schema, Audience: ArtifactManifestAudience, Purpose: ArtifactManifestPurpose,
		ArtifactID: grant.ArtifactID, Component: grant.Component, Version: grant.Version,
		ProtocolMin: grant.ArtifactProtocolMin, ProtocolMax: grant.ArtifactProtocolMax,
		ArtifactSizeBytes: grant.ArtifactSizeBytes, DigestAlgorithm: grant.DigestAlgorithm,
		SHA256Digest: grant.SHA256Digest, DownloadURL: grant.DownloadURL,
	}
	artifactSignature, err := SignArtifactManifestV2(context.Background(), artifactManifest,
		testSigner{id: "release-command-key", private: commandPrivate})
	if err != nil {
		t.Fatal(err)
	}
	grant.ArtifactManifestSignature = base64.RawURLEncoding.EncodeToString(artifactSignature)
	signedGrant, err := SignUpgradeCommandGrant(context.Background(), grant,
		testSigner{id: "release-command-key", private: commandPrivate})
	if err != nil {
		t.Fatal(err)
	}
	grantWire, _ := signedGrant.Encode()
	grantKeys := NewKeyRing()
	_ = grantKeys.Add("release-command-key", commandPublic)

	executionWire, err := IssueCommandExecution(context.Background(), grantWire, grantKeys,
		UpgradeCommandGrantVerifyOptions{Now: now.Add(time.Minute), ExpectedAudience: UpgradeCommandGrantAudience,
			ExpectedInstallationID: grant.InstallationID, ExpectedNodeID: grant.NodeID, ExpectedCommandID: grant.CommandID,
			ExpectedPlanID: grant.PlanID, ExpectedPlanRevision: grant.PlanRevision, ExpectedBatchID: grant.BatchID},
		testSigner{id: "control-execution-1", private: controlPrivate},
		testSigner{id: "edge-consumption-1", private: edgePrivate})
	if err != nil {
		t.Fatalf("IssueCommandExecution() error = %v", err)
	}
	signedExecution, err := DecodeUpgradeExecution(executionWire)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest, _ := CanonicalUpgradeCommandGrantDigest(grantWire)
	execution := signedExecution.Execution
	if execution.Schema != UpgradeExecutionV2Schema || execution.GrantDigest != wantDigest ||
		execution.GrantExpiresAt != grant.ExpiresAt ||
		execution.InstallationID != grant.InstallationID || execution.NodeID != grant.NodeID ||
		execution.CommandID != grant.CommandID || execution.Nonce != grant.Nonce ||
		execution.PlanID != grant.PlanID || execution.PlanRevision != grant.PlanRevision ||
		execution.BatchID != grant.BatchID || execution.ArtifactBundleID != grant.ArtifactBundleID ||
		execution.ArtifactBundleSHA256 != grant.ArtifactBundleSHA256 ||
		execution.CommandIssuanceNotAfter != grant.CommandIssuanceNotAfter ||
		execution.ReleaseSequence != grant.ChannelRevision || execution.Component != grant.Component ||
		execution.Operation != grant.Operation || execution.CurrentVersion != grant.CurrentVersion ||
		execution.TargetVersion != grant.Version || execution.ArtifactID != grant.ArtifactID ||
		execution.SHA256Digest != grant.SHA256Digest || execution.DownloadURL != grant.DownloadURL ||
		execution.ArtifactSizeBytes != grant.ArtifactSizeBytes || execution.Platform != grant.Platform ||
		execution.Architecture != grant.Architecture || !reflect.DeepEqual(execution.Compatibility, grant.Compatibility) ||
		!reflect.DeepEqual(execution.Health, grant.Health) || execution.Rollout != grant.Rollout ||
		execution.Rollback != grant.Rollback || execution.IssuedAt != grant.IssuedAt ||
		execution.NotBefore != grant.NotBefore || execution.ExpiresAt != grant.ExpiresAt {
		t.Fatalf("execution did not derive frozen command grant: %#v", execution)
	}
	controlKeys, edgeKeys := NewKeyRing(), NewKeyRing()
	_ = controlKeys.Add("control-execution-1", controlPublic)
	_ = edgeKeys.Add("edge-consumption-1", edgePublic)
	if _, err := VerifyUpgradeExecution(signedExecution, controlKeys, edgeKeys,
		executionVerifyOptions(now, execution)); err != nil {
		t.Fatalf("VerifyUpgradeExecution() error = %v", err)
	}
	document, err := signedExecution.planSigningDocument()
	if err != nil || document.Domain != upgradeExecutionEdgeSignatureDomainV2 || document.SchemaVersion != 2 ||
		document.PlanID != grant.PlanID || document.Revision != grant.PlanRevision || document.BatchID != grant.BatchID ||
		document.ArtifactBundleID != grant.ArtifactBundleID || document.ArtifactBundleSHA256 != grant.ArtifactBundleSHA256 ||
		document.CommandIssuanceNotAfter != grant.CommandIssuanceNotAfter {
		t.Fatalf("v2 edge signing document = (%#v, %v)", document, err)
	}
	wrongPlan := executionVerifyOptions(now, execution)
	wrongPlan.ExpectedPlanID = "00000000-0000-4000-8000-000000000099"
	if _, err := VerifyUpgradeExecution(signedExecution, controlKeys, edgeKeys, wrongPlan); !errors.Is(err, ErrUpgradeExecutionTargetMismatch) {
		t.Fatalf("execution plan substitution error = %v", err)
	}
	execution.PlanRevision = MaxUpgradePlanRevision + 1
	if err := execution.Validate(); !errors.Is(err, ErrInvalidUpgradeExecution) {
		t.Fatalf("execution plan revision beyond PostgreSQL bigint error = %v", err)
	}
}

func TestIssueCommandExecutionUsesFreshCommandExpiryAfterParentExpiry(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	commandPublic, commandPrivate := upgradeGrantTestKey(0x8b)
	_, controlPrivate := upgradeGrantTestKey(0x8c)
	_, edgePrivate := upgradeGrantTestKey(0x8d)
	grant := validUpgradeCommandGrantV2(t, now, commandPrivate)
	grant.ParentGrantIssuedAt = now.Add(-20 * time.Minute).Unix()
	grant.ParentGrantExpiresAt = now.Add(-5 * time.Minute).Unix()
	grant.CommandIssuanceNotAfter = now.Add(time.Hour).Unix()
	grant.IssuedAt = now.Unix()
	grant.NotBefore = now.Unix()
	grant.ExpiresAt = now.Add(15 * time.Minute).Unix()
	signed, err := SignUpgradeCommandGrant(context.Background(), grant,
		testSigner{id: "release-command-key", private: commandPrivate})
	if err != nil {
		t.Fatal(err)
	}
	wire, err := signed.Encode()
	if err != nil {
		t.Fatal(err)
	}
	ring := NewKeyRing()
	_ = ring.Add("release-command-key", commandPublic)
	executionWire, err := IssueCommandExecution(context.Background(), wire, ring,
		UpgradeCommandGrantVerifyOptions{Now: now, ExpectedAudience: UpgradeCommandGrantAudience,
			ExpectedInstallationID: grant.InstallationID, ExpectedNodeID: grant.NodeID,
			ExpectedCommandID: grant.CommandID, ExpectedPlanID: grant.PlanID,
			ExpectedPlanRevision: grant.PlanRevision, ExpectedBatchID: grant.BatchID},
		testSigner{id: "control-execution-1", private: controlPrivate},
		testSigner{id: "edge-consumption-1", private: edgePrivate})
	if err != nil {
		t.Fatalf("IssueCommandExecution() error = %v", err)
	}
	execution, err := DecodeUpgradeExecution(executionWire)
	if err != nil {
		t.Fatal(err)
	}
	if execution.Execution.GrantExpiresAt != grant.ExpiresAt {
		t.Fatalf("execution grant expiry = %d, want fresh command expiry %d", execution.Execution.GrantExpiresAt, grant.ExpiresAt)
	}
}

func TestIssueCommandExecutionV3DerivesAndSignsDualSequence(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	commandPublic, commandPrivate := upgradeGrantTestKey(0xb1)
	controlPublic, controlPrivate := upgradeGrantTestKey(0xb2)
	edgePublic, edgePrivate := upgradeGrantTestKey(0xb3)
	grant := validUpgradeCommandGrantV2(t, now, commandPrivate)
	grant.Schema = UpgradeCommandGrantV3Schema
	grant.ExecutionSequence = 31
	grant.ReleaseSequence = 12
	manifest := ArtifactManifestV2{
		Schema: ArtifactManifestV3Schema, Audience: ArtifactManifestAudience, Purpose: ArtifactManifestPurpose,
		ArtifactID: grant.ArtifactID, Component: grant.Component, Version: grant.Version,
		ProtocolMin: grant.ArtifactProtocolMin, ProtocolMax: grant.ArtifactProtocolMax,
		ArtifactSizeBytes: grant.ArtifactSizeBytes, ReleaseSequence: grant.ReleaseSequence,
		DigestAlgorithm: grant.DigestAlgorithm, SHA256Digest: grant.SHA256Digest, DownloadURL: grant.DownloadURL,
	}
	artifactSignature, err := SignArtifactManifestV3(context.Background(), manifest,
		testSigner{id: "release-command-key", private: commandPrivate})
	if err != nil {
		t.Fatal(err)
	}
	grant.ArtifactManifestSignature = base64.RawURLEncoding.EncodeToString(artifactSignature)
	signedGrant, err := SignUpgradeCommandGrant(context.Background(), grant,
		testSigner{id: "release-command-key", private: commandPrivate})
	if err != nil {
		t.Fatal(err)
	}
	grantWire, err := signedGrant.Encode()
	if err != nil {
		t.Fatal(err)
	}
	grantKeys := NewKeyRing()
	_ = grantKeys.Add("release-command-key", commandPublic)
	executionWire, err := IssueCommandExecution(context.Background(), grantWire, grantKeys,
		UpgradeCommandGrantVerifyOptions{Now: now.Add(time.Minute), ExpectedAudience: UpgradeCommandGrantAudience,
			ExpectedInstallationID: grant.InstallationID, ExpectedNodeID: grant.NodeID,
			ExpectedCommandID: grant.CommandID, ExpectedPlanID: grant.PlanID,
			ExpectedPlanRevision: grant.PlanRevision, ExpectedBatchID: grant.BatchID},
		testSigner{id: "control-execution-1", private: controlPrivate},
		testSigner{id: "edge-consumption-1", private: edgePrivate})
	if err != nil {
		t.Fatalf("IssueCommandExecution() error = %v", err)
	}
	signedExecution, err := DecodeUpgradeExecution(executionWire)
	if err != nil {
		t.Fatal(err)
	}
	execution := signedExecution.Execution
	if execution.Schema != UpgradeExecutionV3Schema || execution.ExecutionSequence != grant.ExecutionSequence ||
		execution.ReleaseSequence != grant.ReleaseSequence {
		t.Fatalf("dual sequence execution = %#v, grant = %#v", execution, grant)
	}
	controlKeys, edgeKeys := NewKeyRing(), NewKeyRing()
	_ = controlKeys.Add("control-execution-1", controlPublic)
	_ = edgeKeys.Add("edge-consumption-1", edgePublic)
	options := executionVerifyOptions(now, execution)
	if _, err := VerifyUpgradeExecution(signedExecution, controlKeys, edgeKeys, options); err != nil {
		t.Fatalf("VerifyUpgradeExecution() error = %v", err)
	}
	for _, mutate := range []func(*UpgradeExecution){
		func(value *UpgradeExecution) { value.ExecutionSequence++ },
		func(value *UpgradeExecution) { value.ReleaseSequence++ },
	} {
		tampered := signedExecution
		mutate(&tampered.Execution)
		if _, err := VerifyUpgradeExecution(tampered, controlKeys, edgeKeys, options); !errors.Is(err, ErrInvalidUpgradeExecutionControlSignature) {
			t.Fatalf("dual-sequence tamper error = %v", err)
		}
	}
}

func TestLegacyUpgradeExecutionSchemasRejectV3SequenceFields(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	for _, schema := range []string{UpgradeExecutionSchema, UpgradeExecutionV2Schema} {
		execution := validUpgradeExecution(now)
		execution.Schema = schema
		execution.ExecutionSequence = 3
		if err := execution.Validate(); !errors.Is(err, ErrInvalidUpgradeExecution) {
			t.Fatalf("legacy schema %q accepted execution_sequence: %v", schema, err)
		}
	}
}

func validUpgradeExecution(now time.Time) UpgradeExecution {
	return UpgradeExecution{
		Schema: UpgradeExecutionSchema, Audience: UpgradeExecutionAudience,
		Purpose: UpgradeExecutionPurpose, Action: UpgradeExecutionAction,
		GrantDigestAlgorithm: "sha256",
		GrantDigest:          base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x31}, sha256.Size)),
		GrantExpiresAt:       now.Add(15 * time.Minute).Unix(),
		InstallationID:       "00000000-0000-4000-8000-000000000004",
		NodeID:               "00000000-0000-4000-8000-000000000021",
		CommandID:            "00000000-0000-4000-8000-000000000022",
		Nonce:                "00000000-0000-4000-8000-000000000023",
		ReleaseSequence:      7,
		Component:            "edge-agent", Operation: UpgradeOperation,
		CurrentVersion: "1.0.0", TargetVersion: "2.0.0",
		ArtifactID:        "00000000-0000-4000-8000-000000000010",
		DigestAlgorithm:   "sha256",
		SHA256Digest:      base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, sha256.Size)),
		DownloadURL:       "https://cdn.example/releases/edge-agent-2.0.0",
		ArtifactSizeBytes: 1024, Platform: "linux", Architecture: "amd64",
		Compatibility: UpgradeExecutionCompatibility{MinAgentVersion: "1.0.0", MaxAgentVersion: "2.0.0"},
		Health: UpgradeExecutionHealthPolicy{
			Command: []string{"{artifact}", "health"}, ActivationTimeoutNanoseconds: int64(30 * time.Second),
			ObservationWindowNanoseconds: int64(time.Minute), IntervalNanoseconds: int64(time.Second),
			ProbeTimeoutNanoseconds: int64(500 * time.Millisecond), RequiredConsecutiveSuccesses: 3,
		},
		Rollout:  UpgradeExecutionRolloutPolicy{Percentage: 100},
		Rollback: UpgradeExecutionRollbackPolicy{Automatic: true},
		IssuedAt: now.Unix(), NotBefore: now.Add(time.Minute).Unix(), ExpiresAt: now.Add(10 * time.Minute).Unix(),
	}
}

func executionVerifyOptions(now time.Time, execution UpgradeExecution) UpgradeExecutionVerifyOptions {
	return UpgradeExecutionVerifyOptions{
		Now: now.Add(2 * time.Minute), ExpectedAudience: UpgradeExecutionAudience,
		ExpectedInstallationID: execution.InstallationID, ExpectedNodeID: execution.NodeID,
		ExpectedCommandID: execution.CommandID, ExpectedNonce: execution.Nonce,
		ExpectedCurrentVersion: execution.CurrentVersion, ExpectedTargetVersion: execution.TargetVersion,
		ExpectedPlanID: execution.PlanID, ExpectedPlanRevision: execution.PlanRevision,
		ExpectedBatchID: execution.BatchID,
	}
}
