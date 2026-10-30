package certificateasset

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

type publicationRepository41 struct {
	claims            []PublicationIntentLease
	claimErr          error
	settlementErr     error
	completed         []PublicationIntentLease
	completedResults  []PublicationResult
	retried           []publicationSettlement41
	permanent         []publicationSettlement41
	settlementCtxLive bool
}

type publicationSettlement41 struct {
	lease PublicationIntentLease
	code  string
}

func (repository *publicationRepository41) ClaimPublicationIntent(
	_ context.Context,
	_ string,
) (PublicationIntentLease, bool, error) {
	if repository.claimErr != nil {
		return PublicationIntentLease{}, false, repository.claimErr
	}
	if len(repository.claims) == 0 {
		return PublicationIntentLease{}, false, nil
	}
	lease := repository.claims[0]
	repository.claims = repository.claims[1:]
	return lease, true, nil
}

func (repository *publicationRepository41) CompletePublicationIntent(
	ctx context.Context,
	lease PublicationIntentLease,
	result PublicationResult,
) error {
	repository.settlementCtxLive = ctx.Err() == nil
	repository.completed = append(repository.completed, lease)
	repository.completedResults = append(repository.completedResults, result)
	return repository.settlementErr
}

func (repository *publicationRepository41) FailPublicationIntent(
	ctx context.Context,
	lease PublicationIntentLease,
	code string,
) error {
	repository.settlementCtxLive = ctx.Err() == nil
	repository.retried = append(repository.retried, publicationSettlement41{lease: lease, code: code})
	return repository.settlementErr
}

func (repository *publicationRepository41) PermanentlyFailPublicationIntent(
	ctx context.Context,
	lease PublicationIntentLease,
	code string,
) error {
	repository.settlementCtxLive = ctx.Err() == nil
	repository.permanent = append(repository.permanent, publicationSettlement41{lease: lease, code: code})
	return repository.settlementErr
}

type certificatePublisher41 struct {
	publish func(context.Context, CertificatePublicationCommandV1) (PublicationResult, error)
	seen    []CertificatePublicationCommandV1
}

func (publisher *certificatePublisher41) Publish(
	ctx context.Context,
	command CertificatePublicationCommandV1,
) (PublicationResult, error) {
	publisher.seen = append(publisher.seen, command)
	return publisher.publish(ctx, command)
}

func TestPublicationWorkerAckUsesExactVersionedIdentity41(t *testing.T) {
	lease := publicationLease41(7)
	repository := &publicationRepository41{claims: []PublicationIntentLease{lease}}
	publisher := &certificatePublisher41{publish: func(
		context.Context,
		CertificatePublicationCommandV1,
	) (PublicationResult, error) {
		return publicationResult41(), nil
	}}
	worker, err := NewPublicationWorker(repository, publisher, publicationWorkerConfig41())
	if err != nil {
		t.Fatal(err)
	}
	found, err := worker.RunOnce(t.Context())
	if err != nil || !found {
		t.Fatalf("RunOnce()=(%v,%v)", found, err)
	}
	if len(repository.completed) != 1 || len(repository.retried) != 0 || len(repository.permanent) != 0 {
		t.Fatalf("completed=%d retry=%d permanent=%d", len(repository.completed), len(repository.retried), len(repository.permanent))
	}
	want := CertificatePublicationCommandV1{
		Schema: CertificatePublicationSchemaV1, TenantScopeID: lease.TenantScopeID,
		SiteID: lease.SiteID, AssetID: lease.AssetID, VersionID: lease.VersionID,
		BindingRevision: lease.BindingRevision, Operation: lease.Operation, Default: lease.Default,
		RequestID: lease.RequestID, ActorScopeID: lease.ActorScopeID, ActorUserID: lease.ActorUserID,
		ActorSessionID: lease.ActorSessionID, ActorScopeKind: lease.ActorScopeKind,
		ActorUserRevision: lease.ActorUserRevision, TargetTenantID: lease.TargetTenantID,
		TargetTenantRevision: lease.TargetTenantRevision, Deadline: lease.Deadline, CreatedAt: lease.CreatedAt,
		IdempotencyKey: lease.IdempotencyKey,
	}
	if len(publisher.seen) != 1 || publisher.seen[0] != want {
		t.Fatalf("published=%+v want=%+v", publisher.seen, want)
	}
	if len(repository.completedResults) != 1 || repository.completedResults[0] != publicationResult41() {
		t.Fatalf("completed results=%+v", repository.completedResults)
	}
	typeOfCommand := reflect.TypeOf(want)
	for index := 0; index < typeOfCommand.NumField(); index++ {
		name := strings.ToLower(typeOfCommand.Field(index).Name)
		if strings.Contains(name, "private") || strings.Contains(name, "pem") ||
			strings.Contains(name, "ciphertext") || strings.Contains(name, "nonce") {
			t.Fatalf("versioned publication command exposes private material field %q", name)
		}
	}
}

func TestPublicationWorkerSettlesRetryPermanentAndInvalidContract41(t *testing.T) {
	for _, test := range []struct {
		name          string
		result        PublicationResult
		wantRetry     string
		wantPermanent string
		wantErr       error
	}{
		{name: "retry", result: PublicationResult{Outcome: PublicationRetry, FailureCode: "edge_unavailable"}, wantRetry: "edge_unavailable"},
		{name: "permanent", result: PublicationResult{Outcome: PublicationPermanent, FailureCode: "asset_invalid"}, wantPermanent: "asset_invalid"},
		{name: "invalid contract", result: PublicationResult{Outcome: PublicationRetry, FailureCode: "SECRET token"}, wantPermanent: "publisher_contract_invalid", wantErr: ErrPublicationPublisherContract},
		{name: "ack without durable identity", result: PublicationResult{Outcome: PublicationAck}, wantPermanent: "publisher_contract_invalid", wantErr: ErrPublicationPublisherContract},
	} {
		t.Run(test.name, func(t *testing.T) {
			repository := &publicationRepository41{claims: []PublicationIntentLease{publicationLease41(1)}}
			publisher := &certificatePublisher41{publish: func(context.Context, CertificatePublicationCommandV1) (PublicationResult, error) {
				return test.result, nil
			}}
			worker, err := NewPublicationWorker(repository, publisher, publicationWorkerConfig41())
			if err != nil {
				t.Fatal(err)
			}
			found, runErr := worker.RunOnce(t.Context())
			if !found || !errors.Is(runErr, test.wantErr) || strings.Contains(strings.ToLower(runErrString41(runErr)), "secret") {
				t.Fatalf("RunOnce()=(%v,%v)", found, runErr)
			}
			if test.wantRetry != "" && (len(repository.retried) != 1 || repository.retried[0].code != test.wantRetry) {
				t.Fatalf("retry=%+v", repository.retried)
			}
			if test.wantPermanent != "" && (len(repository.permanent) != 1 || repository.permanent[0].code != test.wantPermanent) {
				t.Fatalf("permanent=%+v", repository.permanent)
			}
		})
	}
}

func TestPublicationWorkerSanitizesPublisherErrorPanicAndTimeout41(t *testing.T) {
	tests := []struct {
		name     string
		publish  func(context.Context, CertificatePublicationCommandV1) (PublicationResult, error)
		wantCode string
		wantErr  error
	}{
		{name: "error", publish: func(context.Context, CertificatePublicationCommandV1) (PublicationResult, error) {
			return PublicationResult{}, errors.New("upstream secret token")
		}, wantCode: "publisher_unavailable", wantErr: ErrPublicationPublisherUnavailable},
		{name: "panic", publish: func(context.Context, CertificatePublicationCommandV1) (PublicationResult, error) {
			panic("upstream secret token")
		}, wantCode: "publisher_panic", wantErr: ErrPublicationPublisherPanic},
		{name: "timeout", publish: func(ctx context.Context, _ CertificatePublicationCommandV1) (PublicationResult, error) {
			<-ctx.Done()
			return PublicationResult{}, ctx.Err()
		}, wantCode: "publisher_timeout", wantErr: ErrPublicationPublisherTimeout},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			repository := &publicationRepository41{claims: []PublicationIntentLease{publicationLease41(1)}}
			worker, err := NewPublicationWorker(repository, &certificatePublisher41{publish: test.publish}, publicationWorkerConfig41())
			if err != nil {
				t.Fatal(err)
			}
			found, runErr := worker.RunOnce(t.Context())
			if !found || !errors.Is(runErr, test.wantErr) || strings.Contains(strings.ToLower(runErrString41(runErr)), "secret") {
				t.Fatalf("RunOnce()=(%v,%v)", found, runErr)
			}
			if len(repository.retried) != 1 || repository.retried[0].code != test.wantCode ||
				len(repository.completed) != 0 || len(repository.permanent) != 0 || !repository.settlementCtxLive {
				t.Fatalf("retry=%+v complete=%d permanent=%d contextLive=%v", repository.retried,
					len(repository.completed), len(repository.permanent), repository.settlementCtxLive)
			}
		})
	}
}

func TestPublicationWorkerCancellationStillReleasesLease41(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	repository := &publicationRepository41{claims: []PublicationIntentLease{publicationLease41(1)}}
	publisher := &certificatePublisher41{publish: func(publishCtx context.Context, _ CertificatePublicationCommandV1) (PublicationResult, error) {
		cancel()
		<-publishCtx.Done()
		return PublicationResult{}, publishCtx.Err()
	}}
	worker, err := NewPublicationWorker(repository, publisher, publicationWorkerConfig41())
	if err != nil {
		t.Fatal(err)
	}
	found, runErr := worker.RunOnce(ctx)
	if !found || !errors.Is(runErr, context.Canceled) {
		t.Fatalf("RunOnce()=(%v,%v)", found, runErr)
	}
	if len(repository.retried) != 1 || repository.retried[0].code != "publisher_cancelled" || !repository.settlementCtxLive {
		t.Fatalf("retry=%+v contextLive=%v", repository.retried, repository.settlementCtxLive)
	}
}

func TestPublicationWorkerClaimsOneIntentAndPreservesStoreOrder41(t *testing.T) {
	first, second := publicationLease41(1), publicationLease41(2)
	second.TenantScopeID, second.SiteID = first.TenantScopeID, first.SiteID
	second.IdempotencyKey = publicationIntentIdempotencyKey(second.TenantScopeID, second.SiteID, second.BindingRevision)
	repository := &publicationRepository41{claims: []PublicationIntentLease{first, second}}
	publisher := &certificatePublisher41{publish: func(context.Context, CertificatePublicationCommandV1) (PublicationResult, error) {
		return publicationResult41(), nil
	}}
	worker, err := NewPublicationWorker(repository, publisher, publicationWorkerConfig41())
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if found, runErr := worker.RunOnce(t.Context()); runErr != nil || !found {
			t.Fatalf("RunOnce()=(%v,%v)", found, runErr)
		}
	}
	if len(publisher.seen) != 2 || publisher.seen[0].BindingRevision != 1 || publisher.seen[1].BindingRevision != 2 {
		t.Fatalf("publication order=%+v", publisher.seen)
	}
	if found, runErr := worker.RunOnce(t.Context()); runErr != nil || found {
		t.Fatalf("empty RunOnce()=(%v,%v)", found, runErr)
	}
}

func TestPublicationWorkerValidatesConfigurationAndSettlementFailure41(t *testing.T) {
	valid := publicationWorkerConfig41()
	repository := &publicationRepository41{}
	publisher := &certificatePublisher41{publish: func(context.Context, CertificatePublicationCommandV1) (PublicationResult, error) {
		return publicationResult41(), nil
	}}
	for index, test := range []struct {
		repository PublicationIntentRepository
		publisher  CertificatePublisher
		config     PublicationWorkerConfig
	}{
		{publisher: publisher, config: valid},
		{repository: repository, config: valid},
		{repository: repository, publisher: publisher, config: PublicationWorkerConfig{}},
	} {
		if _, err := NewPublicationWorker(test.repository, test.publisher, test.config); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("invalid config %d error=%v", index, err)
		}
	}

	settlementErr := errors.New("settlement unavailable")
	repository = &publicationRepository41{claims: []PublicationIntentLease{publicationLease41(1)}, settlementErr: settlementErr}
	worker, err := NewPublicationWorker(repository, publisher, valid)
	if err != nil {
		t.Fatal(err)
	}
	if found, runErr := worker.RunOnce(t.Context()); !found || !errors.Is(runErr, settlementErr) {
		t.Fatalf("settlement RunOnce()=(%v,%v)", found, runErr)
	}
	if _, err := worker.RunOnce(nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("nil context error=%v", err)
	}
}

func publicationWorkerConfig41() PublicationWorkerConfig {
	config := DefaultPublicationWorkerConfig()
	config.WorkerID = "certificate-publication-41"
	config.PublishTimeout = 10 * time.Millisecond
	config.SettlementTimeout = time.Second
	return config
}

func publicationLease41(revision int64) PublicationIntentLease {
	tenantID, siteID := uuid.New(), uuid.New()
	createdAt := time.Now()
	return PublicationIntentLease{
		TenantScopeID: tenantID, SiteID: siteID, BindingRevision: revision,
		Operation: "publish", AssetID: uuid.New(), VersionID: uuid.New(), Default: true,
		RequestID: "request-41", ActorScopeID: tenantID, ActorUserID: uuid.New(), ActorSessionID: uuid.New(),
		ActorScopeKind: ScopeTenant, ActorUserRevision: 7, TargetTenantID: uuid.New(), TargetTenantRevision: 11,
		IdempotencyKey: publicationIntentIdempotencyKey(tenantID, siteID, revision),
		StateSequence:  2, Attempt: 1, WorkerID: "certificate-publication-41",
		Token: uuid.New(), ExpiresAt: createdAt.Add(time.Minute), Deadline: createdAt.Add(time.Hour), CreatedAt: createdAt,
	}
}

func publicationResult41() PublicationResult {
	return PublicationResult{
		Outcome: PublicationAck, PublicationID: uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7141"),
		PublicationRevision: 3, ConfigVersionID: uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7142"),
		RolloutID: uuid.MustParse("018f47a2-5b9c-7d31-8a60-104c9c0b7143"), RolloutRevision: 1,
	}
}

func runErrString41(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
