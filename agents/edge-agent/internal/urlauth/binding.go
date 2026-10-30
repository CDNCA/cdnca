package urlauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

func DecodeArtifactBinding(raw []byte) (ArtifactBinding, error) {
	if len(raw) == 0 || len(raw) > MaxArtifactBytes {
		return ArtifactBinding{}, invalid("invalid URL auth artifact")
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return ArtifactBinding{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document ArtifactDocument
	if err := decoder.Decode(&document); err != nil {
		return ArtifactBinding{}, invalid("decode URL auth artifact: %v", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		clearArtifactSecrets(document.Keys)
		return ArtifactBinding{}, invalid("URL auth artifact has trailing data")
	}
	defer clearArtifactSecrets(document.Keys)
	activation := document.Activation
	binding := ArtifactBinding{
		EventID: activation.EventID, DeploymentID: activation.DeploymentID, Attempt: activation.Attempt,
		ConfigVersionID: activation.ConfigVersionID, ArtifactID: activation.ArtifactID, RecipientKeyID: activation.RecipientKeyID,
		PolicyID: activation.PolicyID, TenantID: activation.TenantID, SiteID: activation.SiteID, PolicyVersion: activation.PolicyVersion,
		ConfigurationScopeID: activation.ConfigurationScopeID,
	}
	if document.SchemaVersion != ArtifactSchemaVersion || activation.SchemaVersion != ActivationSchemaVersion ||
		!canonicalArtifactUUID(binding.EventID) || !canonicalArtifactUUID(binding.DeploymentID) || binding.Attempt != 1 ||
		!canonicalArtifactUUID(binding.ConfigVersionID) || !canonicalArtifactUUID(binding.ArtifactID) ||
		!validArtifactRecipientKeyID(binding.RecipientKeyID) || !canonicalArtifactUUID(binding.PolicyID) ||
		!canonicalArtifactUUID(binding.TenantID) || !canonicalArtifactUUID(binding.SiteID) || binding.PolicyVersion == 0 ||
		(binding.ConfigurationScopeID != "" && !canonicalArtifactUUID(binding.ConfigurationScopeID)) ||
		document.Policy.PolicyVersion != binding.PolicyVersion || document.Policy.TenantID != binding.TenantID || document.Policy.SiteID != binding.SiteID {
		return ArtifactBinding{}, invalid("URL auth artifact binding is invalid")
	}
	return binding, nil
}
