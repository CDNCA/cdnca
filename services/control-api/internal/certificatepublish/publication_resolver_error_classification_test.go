package certificatepublish

import (
	"context"
	"fmt"
	"testing"

	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
)

type resolverErrorPublicationService struct {
	publishCalls int
}

func (service *resolverErrorPublicationService) Publish(
	context.Context,
	PublicationRequest,
) (edgedeployment.CreateRolloutResult, error) {
	service.publishCalls++
	return edgedeployment.CreateRolloutResult{}, nil
}

func (*resolverErrorPublicationService) Unpublish(
	context.Context,
	UnpublishRequest,
) (LifecycleResult, error) {
	return LifecycleResult{}, nil
}

type resolverErrorCertificateTargetResolver struct {
	err error
}

func (resolver resolverErrorCertificateTargetResolver) ResolveCertificateTarget(
	context.Context,
	certificateasset.CertificatePublicationCommandV1,
) (policy edgeautopublish.CertificateTargetPolicy, err error) {
	return policy, resolver.err
}

func TestPublisherAdapterClassifiesResolverErrorsBeforePublication(t *testing.T) {
	for _, test := range []struct {
		name        string
		err         error
		wantOutcome certificateasset.PublicationOutcome
		wantCode    string
	}{
		{
			name:        "unauthenticated",
			err:         fmt.Errorf("resolve target: %w", edgedeployment.ErrUnauthenticated),
			wantOutcome: certificateasset.PublicationPermanent,
			wantCode:    "actor_unauthenticated",
		},
		{
			name:        "permission denied",
			err:         fmt.Errorf("resolve target: %w", edgedeployment.ErrPermissionDenied),
			wantOutcome: certificateasset.PublicationPermanent,
			wantCode:    "actor_unauthenticated",
		},
		{
			name:        "idempotency conflict",
			err:         fmt.Errorf("resolve target: %w", edgedeployment.ErrIdempotencyConflict),
			wantOutcome: certificateasset.PublicationPermanent,
			wantCode:    "publication_conflict",
		},
		{
			name:        "unavailable",
			err:         fmt.Errorf("resolve target: %w", edgedeployment.ErrUnavailable),
			wantOutcome: certificateasset.PublicationRetry,
			wantCode:    "publication_unavailable",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			service := &resolverErrorPublicationService{}
			adapter, err := NewPublisherAdapter(service, resolverErrorCertificateTargetResolver{err: test.err})
			if err != nil {
				t.Fatal(err)
			}

			result, err := adapter.Publish(t.Context(), certificateasset.CertificatePublicationCommandV1{})
			if err != nil || result.Outcome != test.wantOutcome || result.FailureCode != test.wantCode {
				t.Fatalf("Publish() result=%+v err=%v", result, err)
			}
			if service.publishCalls != 0 {
				t.Fatalf("Publish() downstream calls=%d, want 0", service.publishCalls)
			}
		})
	}
}
