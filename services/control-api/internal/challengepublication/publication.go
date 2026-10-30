package challengepublication

import (
	"context"
	"slices"

	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
)

func NewSecretArtifactBuilder(producer *ArtifactProducer, material ArtifactMaterial) (edgedeployment.SecretArtifactBuilder, error) {
	if producer == nil {
		return nil, ErrInvalidInput
	}
	document, err := normalizeArtifactDocument(ArtifactBuildRequest{
		EventID:      uuid.MustParse("01990000-0000-7000-8000-000000000001"),
		DeploymentID: uuid.MustParse("01990000-0000-7000-8000-000000000002"), Attempt: 1,
		ConfigVersionID: uuid.MustParse("01990000-0000-7000-8000-000000000003"),
		ArtifactID:      uuid.MustParse("01990000-0000-7000-8000-000000000004"),
	}, material)
	clearArtifactDocument(&document)
	if err != nil {
		return nil, err
	}
	frozen := cloneMaterial(material)
	return func(ctx context.Context, binding edgedeployment.SecretArtifactBinding) (edgedeployment.ArtifactInput, error) {
		return producer.Build(ctx, ArtifactBuildRequest{
			EventID: binding.EventID, DeploymentID: binding.DeploymentID, Attempt: binding.Attempt,
			ConfigVersionID: binding.ConfigVersionID, ArtifactID: binding.ArtifactID,
			RecipientKeyID: binding.RecipientKeyID, RecipientPublicKey: binding.RecipientPublicKey,
		}, frozen)
	}, nil
}

func cloneMaterial(material ArtifactMaterial) ArtifactMaterial {
	result := material
	result.Policy.TrustedProxies = slices.Clone(material.Policy.TrustedProxies)
	result.Policy.BypassRoutes = slices.Clone(material.Policy.BypassRoutes)
	result.Policy.Rules = slices.Clone(material.Policy.Rules)
	result.Keys = make([]ArtifactSecret, len(material.Keys))
	for index := range material.Keys {
		result.Keys[index] = ArtifactSecret{KeyID: material.Keys[index].KeyID, Secret: slices.Clone(material.Keys[index].Secret)}
	}
	result.ExternalCredentials = make([]ExternalCredential, len(material.ExternalCredentials))
	for index := range material.ExternalCredentials {
		result.ExternalCredentials[index] = material.ExternalCredentials[index]
		result.ExternalCredentials[index].Secret = slices.Clone(material.ExternalCredentials[index].Secret)
	}
	return result
}
