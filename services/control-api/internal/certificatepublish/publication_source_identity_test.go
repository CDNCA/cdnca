package certificatepublish

import (
	"testing"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/certificateasset"
	"github.com/cdnca/cdnca/services/control-api/internal/edgeautopublish"
	"github.com/cdnca/cdnca/services/control-api/internal/edgedeployment"
	"github.com/google/uuid"
)

func TestDNS06PublicationIdentityBindsCertificateSourceRevision(t *testing.T) {
	command := certificatePublicationCommand47()
	command.Deadline = time.Now().UTC().Add(time.Minute)
	nodeID := uuid.New()
	rollout := edgedeployment.Rollout{
		ID: uuid.New(), ConfigurationScopeID: command.TenantScopeID,
		ConfigVersionID: uuid.New(), Revision: 3,
	}
	service := &publicationAdapterService47{
		publishResult: edgedeployment.CreateRolloutResult{Rollout: rollout},
		receipt:       terminalReceipt47(rollout, edgedeployment.CertificatePublicationReceiptSucceeded),
	}
	newAdapter := func(targetNodeID uuid.UUID) *PublisherAdapter {
		adapter, err := NewPublisherAdapter(service, publicationTargetResolver47{
			policy: edgeautopublish.CertificateTargetPolicy{
				NodeIDs: []uuid.UUID{targetNodeID}, ActivationTimeout: time.Second,
				ObservationWindow: time.Second, RequiredConsecutiveSuccesses: 1,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return adapter
	}
	publish := func(adapter *PublisherAdapter, request certificateasset.CertificatePublicationCommandV1) uuid.UUID {
		result, err := adapter.Publish(t.Context(), request)
		if err != nil || result.Outcome != certificateasset.PublicationAck || result.PublicationID == uuid.Nil {
			t.Fatalf("Publish() result=%+v err=%v", result, err)
		}
		return result.PublicationID
	}

	adapter := newAdapter(nodeID)
	baseline := publish(adapter, command)
	if replayed := publish(adapter, command); replayed != baseline {
		t.Fatalf("identical replay publication_id=%s want=%s", replayed, baseline)
	}

	mutations := map[string]func(*certificateasset.CertificatePublicationCommandV1){
		"site":                func(value *certificateasset.CertificatePublicationCommandV1) { value.SiteID = uuid.New() },
		"asset":               func(value *certificateasset.CertificatePublicationCommandV1) { value.AssetID = uuid.New() },
		"certificate version": func(value *certificateasset.CertificatePublicationCommandV1) { value.VersionID = uuid.New() },
		"binding revision":    func(value *certificateasset.CertificatePublicationCommandV1) { value.BindingRevision++ },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := command
			mutate(&changed)
			if got := publish(adapter, changed); got == baseline {
				t.Fatalf("source mutation reused publication_id=%s", got)
			}
		})
	}
	if got := publish(newAdapter(uuid.New()), command); got == baseline {
		t.Fatalf("node target mutation reused publication_id=%s", got)
	}
}
