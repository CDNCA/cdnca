package dnscredentialrewraphttp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cdnca/cdnca/services/control-api/internal/dnsacme"
	"github.com/google/uuid"
)

type Service struct {
	repository Repository
	rewrapper  Rewrapper
}

func NewService(repository Repository, rewrapper Rewrapper) (*Service, error) {
	if repository == nil || rewrapper == nil {
		return nil, ErrInvalidConfig
	}
	return &Service{repository: repository, rewrapper: rewrapper}, nil
}

func (service *Service) Submit(ctx context.Context, request SubmitRequest) (Job, bool, error) {
	if service == nil || ctx == nil || !validSubmitRequest(request) {
		return Job{}, false, ErrInvalidRequest
	}
	digest, err := submitDigest(request)
	if err != nil {
		return Job{}, false, ErrUnavailable
	}
	claim, err := service.repository.Claim(ctx, ClaimRequest{
		Owner: request.Owner, IdempotencyKey: request.IdempotencyKey, Digest: digest,
		Items: append([]BatchItem(nil), request.Items...),
	})
	if err != nil {
		return Job{}, false, err
	}
	if claim.Complete {
		if !validJob(claim.Job) || claim.Job.ID != claim.ID {
			return Job{}, false, ErrUnavailable
		}
		return replayJob(claim.Job), true, nil
	}
	if claim.ID == uuid.Nil || claim.CreatedAt.IsZero() || claim.UpdatedAt.IsZero() ||
		claim.UpdatedAt.Before(claim.CreatedAt) || !sameBatchItems(claim.Items, request.Items) {
		return Job{}, false, ErrUnavailable
	}
	job := processingJob(claim)
	acquired, err := service.repository.WithJobLock(ctx, claim.ID, func(lockContext context.Context) error {
		progress := make([]ItemProgress, len(claim.Items))
		for ordinal, item := range claim.Items {
			stored, complete, itemErr := service.repository.Item(lockContext, request.Owner, claim.ID, ordinal)
			if itemErr != nil {
				return itemErr
			}
			if complete {
				if !validTerminalItem(stored, item) {
					return ErrUnavailable
				}
				progress[ordinal] = stored
				continue
			}
			result, itemErr := service.rewrapItem(lockContext, request, item)
			if itemErr != nil {
				return itemErr
			}
			result, itemErr = service.repository.CompleteItem(lockContext, CompleteItemRequest{
				Owner: request.Owner, JobID: claim.ID, Ordinal: ordinal, Item: result,
			})
			if itemErr != nil || !validTerminalItem(result, item) {
				if itemErr != nil {
					return itemErr
				}
				return ErrUnavailable
			}
			progress[ordinal] = result
		}
		job = completedJob(claim, progress)
		stored, completeErr := service.repository.Complete(lockContext, CompleteRequest{Owner: request.Owner, Job: job})
		if completeErr != nil {
			return completeErr
		}
		if !validJob(stored) || stored.ID != claim.ID {
			return ErrUnavailable
		}
		job = stored
		return nil
	})
	if err != nil {
		return Job{}, false, err
	}
	if !acquired {
		current, getErr := service.repository.Get(ctx, GetRequest{Owner: request.Owner, JobID: claim.ID})
		if getErr != nil {
			return Job{}, false, getErr
		}
		return current, false, nil
	}
	return job, false, nil
}

func (service *Service) Get(ctx context.Context, request GetRequest) (Job, error) {
	if service == nil || ctx == nil || !request.Owner.valid() || request.JobID == uuid.Nil {
		return Job{}, ErrInvalidRequest
	}
	job, err := service.repository.Get(ctx, request)
	if err != nil {
		return Job{}, err
	}
	if !validJob(job) || job.ID != request.JobID {
		return Job{}, ErrUnavailable
	}
	return job, nil
}

func (service *Service) rewrapItem(ctx context.Context, request SubmitRequest, item BatchItem) (ItemProgress, error) {
	key := deriveItemIdempotencyKey(request.Owner.SessionID, request.IdempotencyKey, item.ProviderID)
	replayed, err := service.repository.ItemCompleted(ctx, request.Owner, key)
	if err != nil {
		return ItemProgress{}, err
	}
	progress, rewrapErr := service.rewrapper.RewrapProviderCredentials(ctx, dnsacme.Actor{
		UserID: request.Owner.UserID, ScopeID: request.Owner.ScopeID, ScopeKind: "platform",
	}, dnsacme.CredentialRewrapRequest{
		RequestID: request.RequestID,
		Items: []dnsacme.CredentialRewrapItem{{
			ProviderID: item.ProviderID, ExpectedRevision: item.ExpectedRevision, IdempotencyKey: key,
		}},
	})
	if ctx.Err() != nil {
		return ItemProgress{}, ctx.Err()
	}
	result := ItemProgress{ProviderID: item.ProviderID, ExpectedRevision: item.ExpectedRevision}
	if rewrapErr != nil {
		switch {
		case errors.Is(rewrapErr, dnsacme.ErrRevisionConflict):
			result.Status, result.ErrorCode = ItemConflict, ItemCodeRevisionConflict
		case errors.Is(rewrapErr, dnsacme.ErrNotFound):
			result.Status, result.ErrorCode = ItemFailed, ItemCodeProviderNotFound
		case errors.Is(rewrapErr, dnsacme.ErrCredentialUnavailable):
			result.Status, result.ErrorCode = ItemFailed, ItemCodeCredentialUnavailable
		case errors.Is(rewrapErr, dnsacme.ErrIdempotencyConflict):
			result.Status, result.ErrorCode = ItemFailed, ItemCodeIdempotencyConflict
		default:
			result.Status, result.ErrorCode = ItemFailed, ItemCodeOperationFailed
		}
		return result, nil
	}
	if progress.Requested != 1 || progress.Completed != 1 || progress.NextIndex != 1 || len(progress.Items) != 1 ||
		progress.Items[0].ProviderID != item.ProviderID || progress.Items[0].Revision < 1 || progress.Items[0].CredentialVersion < 1 {
		result.Status, result.ErrorCode = ItemFailed, ItemCodeOperationFailed
		return result, nil
	}
	result.Status = ItemCompleted
	if replayed {
		result.Status = ItemReplayed
	}
	result.Revision = progress.Items[0].Revision
	result.CredentialVersion = progress.Items[0].CredentialVersion
	return result, nil
}

func validSubmitRequest(request SubmitRequest) bool {
	if !request.Owner.valid() || !metadataPattern.MatchString(request.IdempotencyKey) ||
		!metadataPattern.MatchString(request.RequestID) || len(request.Items) == 0 || len(request.Items) > MaxBatchItems {
		return false
	}
	providers := make(map[uuid.UUID]struct{}, len(request.Items))
	for _, item := range request.Items {
		if item.ProviderID == uuid.Nil || item.ExpectedRevision < 1 {
			return false
		}
		if _, duplicate := providers[item.ProviderID]; duplicate {
			return false
		}
		providers[item.ProviderID] = struct{}{}
	}
	return true
}

func submitDigest(request SubmitRequest) ([32]byte, error) {
	payload, err := json.Marshal(struct {
		Version   int         `json:"version"`
		UserID    uuid.UUID   `json:"user_id"`
		ScopeID   uuid.UUID   `json:"scope_id"`
		SessionID uuid.UUID   `json:"session_id"`
		Items     []BatchItem `json:"items"`
	}{1, request.Owner.UserID, request.Owner.ScopeID, request.Owner.SessionID, request.Items})
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(payload), nil
}

func deriveItemIdempotencyKey(sessionID uuid.UUID, batchKey string, providerID uuid.UUID) string {
	digest := sha256.Sum256([]byte("dns-credential-rewrap-item/v1\x00" + sessionID.String() + "\x00" + batchKey + "\x00" + providerID.String()))
	return "rewrap-" + hex.EncodeToString(digest[:])
}

func processingJob(claim Claim) Job {
	items := make([]ItemProgress, len(claim.Items))
	for index, item := range claim.Items {
		items[index] = ItemProgress{
			ProviderID: item.ProviderID, ExpectedRevision: item.ExpectedRevision, Status: ItemPending,
		}
	}
	return Job{
		ID: claim.ID, State: JobProcessing, Requested: len(items), Items: items,
		CreatedAt: claim.CreatedAt.UTC(), UpdatedAt: claim.UpdatedAt.UTC(),
	}
}

func completedJob(claim Claim, items []ItemProgress) Job {
	job := Job{
		ID: claim.ID, State: JobCompleted, Requested: len(items), Completed: len(items),
		Items: append([]ItemProgress(nil), items...), CreatedAt: claim.CreatedAt.UTC(), UpdatedAt: claim.UpdatedAt.UTC(),
	}
	for _, item := range items {
		switch item.Status {
		case ItemCompleted:
			job.Succeeded++
		case ItemReplayed:
			job.Succeeded++
			job.Replayed++
		case ItemConflict:
			job.Conflicted++
		case ItemFailed:
			job.Failed++
		}
	}
	if job.Conflicted != 0 || job.Failed != 0 {
		job.State = JobCompletedWithErrors
	}
	return job
}

func replayJob(stored Job) Job {
	result := stored
	result.Items = append([]ItemProgress(nil), stored.Items...)
	for index := range result.Items {
		if result.Items[index].Status == ItemCompleted {
			result.Items[index].Status = ItemReplayed
			result.Replayed++
		}
	}
	return result
}

func validTerminalItem(progress ItemProgress, expected BatchItem) bool {
	if progress.ProviderID != expected.ProviderID || progress.ExpectedRevision != expected.ExpectedRevision {
		return false
	}
	switch progress.Status {
	case ItemCompleted, ItemReplayed:
		return progress.Revision >= 1 && progress.CredentialVersion >= 1 && progress.ErrorCode == ""
	case ItemConflict:
		return progress.Revision == 0 && progress.CredentialVersion == 0 && progress.ErrorCode == ItemCodeRevisionConflict
	case ItemFailed:
		return progress.Revision == 0 && progress.CredentialVersion == 0 && progress.ErrorCode != ""
	default:
		return false
	}
}

func sameBatchItems(left, right []BatchItem) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func intentDigest(owner Owner, jobID uuid.UUID, ordinal int, item BatchItem) [32]byte {
	return sha256.Sum256([]byte(fmt.Sprintf("dns-credential-rewrap-intent/v1\x00%s\x00%s\x00%d\x00%s\x00%d",
		owner.SessionID, jobID, ordinal, item.ProviderID, item.ExpectedRevision)))
}
