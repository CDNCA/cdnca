package jobhttp

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
)

type Service struct {
	reader     Reader
	settlement SettlementReader
	commands   CommandStore
	producers  map[string]ProducerCommandRouter
	cursor     cursorCodec
}

type ServiceConfig struct {
	ActiveCursorKeyID string
	CursorKeys        map[string][]byte
	// ProducerCommands routes cancel/retry of the listed kinds to their producer.
	ProducerCommands map[string]ProducerCommandRouter
}

func NewService(reader Reader, config ServiceConfig) (*Service, error) {
	if reader == nil {
		return nil, ErrInvalidRequest
	}
	cursor, err := newCursorCodec(config)
	if err != nil {
		return nil, err
	}
	commands, _ := reader.(CommandStore)
	settlement, _ := reader.(SettlementReader)
	producers := make(map[string]ProducerCommandRouter, len(config.ProducerCommands))
	for kind, router := range config.ProducerCommands {
		if router == nil || !stableIdentifierPattern.MatchString(kind) {
			return nil, ErrInvalidRequest
		}
		producers[kind] = router
	}
	return &Service{reader: reader, settlement: settlement, commands: commands, producers: producers, cursor: cursor}, nil
}

func (service *Service) List(ctx context.Context, principal Principal, input ListRequest) (JobPage, error) {
	if ctx == nil {
		return JobPage{}, ErrInvalidRequest
	}
	request, err := normalizeListRequest(input)
	if err != nil {
		return JobPage{}, err
	}
	scope, err := authorize(principal, request.Audience)
	if err != nil {
		return JobPage{}, err
	}
	if request.Audience == AudienceTenant && request.TenantID != nil {
		return JobPage{}, ErrScopeForbidden
	}
	query := ListQuery{
		TenantID: request.TenantID, TaskID: request.TaskID, States: request.States, Kind: request.Kind, Resource: request.Resource,
		From: request.From, To: request.To, Limit: request.Limit + 1,
	}
	if request.Page > 0 {
		return service.numberedPage(ctx, scope, request, query)
	}
	if request.Cursor != "" {
		var cursor listCursor
		if err := service.cursor.decode("jobs", request.Cursor, &cursor); err != nil || !sameListBinding(cursor, scope, request) {
			return JobPage{}, ErrInvalidRequest
		}
		query.AfterCreated = &cursor.CreatedAt
		query.AfterTaskID = &cursor.TaskID
	}
	jobs, err := service.reader.List(ctx, scope, query)
	if err != nil {
		return JobPage{}, normalizeReaderError(ctx, err)
	}
	if err := validateJobPage(jobs, query); err != nil {
		return JobPage{}, err
	}
	page := JobPage{
		Data: jobs,
		Query: QueryMeta{
			From: request.From.Format(time.RFC3339Nano),
			To:   request.To.Format(time.RFC3339Nano),
		},
	}
	if len(jobs) > request.Limit {
		last := jobs[request.Limit-1]
		page.Data = jobs[:request.Limit]
		page.Page.NextCursor, err = service.cursor.encode("jobs", listCursor{
			Version: cursorVersion, Endpoint: "jobs", Scope: cursorScope{Kind: scope.Kind, ID: scope.ID},
			TenantID: cloneUUID(request.TenantID), FilterTaskID: cloneUUID(request.TaskID), States: slices.Clone(request.States), Kind: request.Kind,
			Resource: request.Resource, From: request.From, To: request.To,
			CreatedAt: last.CreatedAt, TaskID: last.TaskID,
		})
		if err != nil {
			return JobPage{}, err
		}
	}
	if page.Data == nil {
		page.Data = []Job{}
	}
	return page, nil
}

func (service *Service) Get(ctx context.Context, principal Principal, audience Audience, taskID uuid.UUID) (Job, error) {
	if ctx == nil || taskID == uuid.Nil {
		return Job{}, ErrInvalidRequest
	}
	scope, err := authorize(principal, audience)
	if err != nil {
		return Job{}, err
	}
	job, err := service.reader.Get(ctx, scope, taskID)
	if err != nil {
		return Job{}, normalizeReaderError(ctx, err)
	}
	if err := validateJob(job); err != nil || job.TaskID != taskID {
		return Job{}, ErrInvalidStoreResponse
	}
	return job, nil
}

func (service *Service) Attempts(ctx context.Context, principal Principal, input ChildPageRequest) (AttemptPage, error) {
	request, scope, err := service.prepareChildRequest(ctx, principal, input)
	if err != nil {
		return AttemptPage{}, err
	}
	query := AttemptQuery{Limit: request.Limit + 1}
	if request.Cursor != "" {
		var cursor attemptCursor
		if err := service.cursor.decode("attempts", request.Cursor, &cursor); err != nil || cursor.Version != cursorVersion ||
			cursor.Endpoint != "attempts" || cursor.Scope != (cursorScope{Kind: scope.Kind, ID: scope.ID}) ||
			cursor.TaskID != request.TaskID || cursor.Attempt == 0 {
			return AttemptPage{}, ErrInvalidRequest
		}
		query.AfterAttempt = &cursor.Attempt
	}
	if err := service.requireVisibleJob(ctx, scope, request.TaskID); err != nil {
		return AttemptPage{}, err
	}
	attempts, err := service.reader.Attempts(ctx, scope, request.TaskID, query)
	if err != nil {
		return AttemptPage{}, normalizeReaderError(ctx, err)
	}
	if err := validateAttemptPage(attempts, query); err != nil {
		return AttemptPage{}, err
	}
	page := AttemptPage{Data: attempts}
	if len(attempts) > request.Limit {
		last := attempts[request.Limit-1]
		page.Data = attempts[:request.Limit]
		page.Page.NextCursor, err = service.cursor.encode("attempts", attemptCursor{
			Version: cursorVersion, Endpoint: "attempts", Scope: cursorScope{Kind: scope.Kind, ID: scope.ID},
			TaskID: request.TaskID, Attempt: last.Number,
		})
		if err != nil {
			return AttemptPage{}, err
		}
	}
	if page.Data == nil {
		page.Data = []Attempt{}
	}
	return page, nil
}

func (service *Service) Results(ctx context.Context, principal Principal, input ChildPageRequest) (ResultPage, error) {
	request, scope, err := service.prepareChildRequest(ctx, principal, input)
	if err != nil {
		return ResultPage{}, err
	}
	query := ResultQuery{Limit: request.Limit + 1}
	if request.Cursor != "" {
		var cursor resultCursor
		if err := service.cursor.decode("results", request.Cursor, &cursor); err != nil || cursor.Version != cursorVersion ||
			cursor.Endpoint != "results" || cursor.Scope != (cursorScope{Kind: scope.Kind, ID: scope.ID}) ||
			cursor.TaskID != request.TaskID || cursor.Ordinal <= 0 {
			return ResultPage{}, ErrInvalidRequest
		}
		query.AfterOrdinal = &cursor.Ordinal
	}
	if err := service.requireVisibleJob(ctx, scope, request.TaskID); err != nil {
		return ResultPage{}, err
	}
	results, err := service.reader.Results(ctx, scope, request.TaskID, query)
	if err != nil {
		return ResultPage{}, normalizeReaderError(ctx, err)
	}
	if err := validateResultPage(results, query); err != nil {
		return ResultPage{}, err
	}
	page := ResultPage{Data: results}
	if len(results) > request.Limit {
		last := results[request.Limit-1]
		page.Data = results[:request.Limit]
		page.Page.NextCursor, err = service.cursor.encode("results", resultCursor{
			Version: cursorVersion, Endpoint: "results", Scope: cursorScope{Kind: scope.Kind, ID: scope.ID},
			TaskID: request.TaskID, Ordinal: last.Ordinal,
		})
		if err != nil {
			return ResultPage{}, err
		}
	}
	if page.Data == nil {
		page.Data = []ItemResult{}
	}
	return page, nil
}

type receiptCursor struct {
	Version  int         `json:"version"`
	Endpoint string      `json:"endpoint"`
	Scope    cursorScope `json:"scope"`
	TaskID   uuid.UUID   `json:"task_id"`
	Attempt  uint32      `json:"attempt"`
	Ordinal  int         `json:"ordinal"`
}

type deadLetterCursor struct {
	Version  int         `json:"version"`
	Endpoint string      `json:"endpoint"`
	Scope    cursorScope `json:"scope"`
	TaskID   uuid.UUID   `json:"task_id"`
	Attempt  uint32      `json:"attempt"`
}

func (service *Service) Receipts(ctx context.Context, principal Principal, input ChildPageRequest) (ReceiptPage, error) {
	request, scope, err := service.prepareChildRequest(ctx, principal, input)
	if err != nil {
		return ReceiptPage{}, err
	}
	if service.settlement == nil {
		return ReceiptPage{}, ErrStoreUnavailable
	}
	query := ReceiptQuery{Limit: request.Limit + 1}
	if request.Cursor != "" {
		var cursor receiptCursor
		if err := service.cursor.decode("receipts", request.Cursor, &cursor); err != nil ||
			cursor.Version != cursorVersion || cursor.Endpoint != "receipts" ||
			cursor.Scope != (cursorScope{Kind: scope.Kind, ID: scope.ID}) ||
			cursor.TaskID != request.TaskID || cursor.Attempt == 0 || cursor.Ordinal <= 0 {
			return ReceiptPage{}, ErrInvalidRequest
		}
		query.AfterAttempt, query.AfterOrdinal = &cursor.Attempt, &cursor.Ordinal
	}
	if err := service.requireVisibleJob(ctx, scope, request.TaskID); err != nil {
		return ReceiptPage{}, err
	}
	receipts, err := service.settlement.Receipts(ctx, scope, request.TaskID, query)
	if err != nil {
		return ReceiptPage{}, normalizeReaderError(ctx, err)
	}
	if err := validateReceiptPage(receipts, query); err != nil {
		return ReceiptPage{}, err
	}
	page := ReceiptPage{Data: receipts}
	if len(receipts) > request.Limit {
		last := receipts[request.Limit-1]
		page.Data = receipts[:request.Limit]
		page.Page.NextCursor, err = service.cursor.encode("receipts", receiptCursor{
			Version: cursorVersion, Endpoint: "receipts", Scope: cursorScope{Kind: scope.Kind, ID: scope.ID},
			TaskID: request.TaskID, Attempt: last.Attempt, Ordinal: last.Ordinal,
		})
		if err != nil {
			return ReceiptPage{}, err
		}
	}
	if page.Data == nil {
		page.Data = []SettlementReceipt{}
	}
	return page, nil
}

func (service *Service) DeadLetters(ctx context.Context, principal Principal, input ChildPageRequest) (DeadLetterPage, error) {
	request, scope, err := service.prepareChildRequest(ctx, principal, input)
	if err != nil {
		return DeadLetterPage{}, err
	}
	if service.settlement == nil {
		return DeadLetterPage{}, ErrStoreUnavailable
	}
	query := DeadLetterQuery{Limit: request.Limit + 1}
	if request.Cursor != "" {
		var cursor deadLetterCursor
		if err := service.cursor.decode("dead-letters", request.Cursor, &cursor); err != nil ||
			cursor.Version != cursorVersion || cursor.Endpoint != "dead-letters" ||
			cursor.Scope != (cursorScope{Kind: scope.Kind, ID: scope.ID}) ||
			cursor.TaskID != request.TaskID || cursor.Attempt == 0 {
			return DeadLetterPage{}, ErrInvalidRequest
		}
		query.AfterAttempt = &cursor.Attempt
	}
	if err := service.requireVisibleJob(ctx, scope, request.TaskID); err != nil {
		return DeadLetterPage{}, err
	}
	letters, err := service.settlement.DeadLetters(ctx, scope, request.TaskID, query)
	if err != nil {
		return DeadLetterPage{}, normalizeReaderError(ctx, err)
	}
	if err := validateDeadLetterPage(letters, query); err != nil {
		return DeadLetterPage{}, err
	}
	page := DeadLetterPage{Data: letters}
	if len(letters) > request.Limit {
		last := letters[request.Limit-1]
		page.Data = letters[:request.Limit]
		page.Page.NextCursor, err = service.cursor.encode("dead-letters", deadLetterCursor{
			Version: cursorVersion, Endpoint: "dead-letters", Scope: cursorScope{Kind: scope.Kind, ID: scope.ID},
			TaskID: request.TaskID, Attempt: last.Attempt,
		})
		if err != nil {
			return DeadLetterPage{}, err
		}
	}
	if page.Data == nil {
		page.Data = []DeadLetter{}
	}
	return page, nil
}

func (service *Service) prepareChildRequest(
	ctx context.Context,
	principal Principal,
	input ChildPageRequest,
) (ChildPageRequest, ReadScope, error) {
	if ctx == nil {
		return ChildPageRequest{}, ReadScope{}, ErrInvalidRequest
	}
	request, err := normalizeChildRequest(input)
	if err != nil {
		return ChildPageRequest{}, ReadScope{}, err
	}
	scope, err := authorize(principal, request.Audience)
	if err != nil {
		return ChildPageRequest{}, ReadScope{}, err
	}
	return request, scope, nil
}

func (service *Service) requireVisibleJob(ctx context.Context, scope ReadScope, taskID uuid.UUID) error {
	job, err := service.reader.Get(ctx, scope, taskID)
	if err != nil {
		return normalizeReaderError(ctx, err)
	}
	if err := validateJob(job); err != nil || job.TaskID != taskID {
		return ErrInvalidStoreResponse
	}
	return nil
}

func authorize(principal Principal, audience Audience) (ReadScope, error) {
	if principal.UserID == uuid.Nil || principal.ScopeID == uuid.Nil {
		return ReadScope{}, ErrPermissionDenied
	}
	switch audience {
	case AudiencePlatform:
		if principal.ScopeKind != ScopePlatform ||
			(!principal.HasPermission(PermissionReadAll) && !principal.HasPermission(PermissionAdmin)) {
			return ReadScope{}, ErrPermissionDenied
		}
	case AudienceTenant:
		if principal.ScopeKind != ScopeTenant || !principal.HasPermission(PermissionRead) {
			return ReadScope{}, ErrPermissionDenied
		}
	default:
		return ReadScope{}, ErrInvalidRequest
	}
	return ReadScope{Kind: principal.ScopeKind, ID: principal.ScopeID}, nil
}

func normalizeReaderError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	switch {
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrStoreUnavailable), errors.Is(err, ErrInvalidStoreResponse),
		errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	default:
		return fmt.Errorf("%w", ErrStoreUnavailable)
	}
}

func validateJobPage(jobs []Job, query ListQuery) error {
	if len(jobs) > query.Limit {
		return ErrInvalidStoreResponse
	}
	for index, job := range jobs {
		if validateJob(job) != nil || job.CreatedAt.Before(query.From) || !job.CreatedAt.Before(query.To) ||
			(query.TenantID != nil && job.TenantID != *query.TenantID) ||
			(query.TaskID != nil && job.TaskID != *query.TaskID) ||
			(query.Kind != "" && job.Kind != query.Kind) ||
			(query.Resource != "" && job.RelatedResource.Reference != query.Resource && !job.resourceMatchedByNode) ||
			(query.Resource == "" && job.resourceMatchedByNode) ||
			(len(query.States) > 0 && !slices.Contains(query.States, job.Status)) {
			return ErrInvalidStoreResponse
		}
		if query.AfterCreated != nil && !jobBefore(job, *query.AfterCreated, *query.AfterTaskID) {
			return ErrInvalidStoreResponse
		}
		if index > 0 && !jobBefore(job, jobs[index-1].CreatedAt, jobs[index-1].TaskID) {
			return ErrInvalidStoreResponse
		}
	}
	return nil
}

func jobBefore(job Job, createdAt time.Time, taskID uuid.UUID) bool {
	return job.CreatedAt.Before(createdAt) || job.CreatedAt.Equal(createdAt) && job.TaskID.String() < taskID.String()
}

func validateJob(job Job) error {
	progress := job.Progress
	if job.TaskID == uuid.Nil || job.TenantID == uuid.Nil || !stableIdentifierPattern.MatchString(job.Kind) ||
		!validSafeText(job.RelatedResource.Reference, 512) || !validSafeText(job.RequestID, 128) ||
		!validOptionalSafeText(job.TraceID, 512) || !jobRevisionPattern.MatchString(job.Revision) ||
		!validState(job.Status) || job.MaxAttempts == 0 ||
		job.MaxAttempts > maximumJobAttempts || job.Attempt > job.MaxAttempts ||
		progress.Total <= 0 || progress.Completed < 0 || progress.Succeeded < 0 ||
		progress.Failed < 0 || progress.Cancelled < 0 || progress.Pending < 0 ||
		progress.Completed != progress.Succeeded+progress.Failed+progress.Cancelled ||
		progress.Total != progress.Completed+progress.Pending || job.CreatedAt.IsZero() || job.UpdatedAt.Before(job.CreatedAt) ||
		(job.FailureCode != "" && !stableIdentifierPattern.MatchString(job.FailureCode)) {
		return ErrInvalidStoreResponse
	}
	terminal := job.Status == StateSucceeded || job.Status == StatePartialFailed || job.Status == StateFailed || job.Status == StateCancelled
	if terminal != (job.CompletedAt != nil) || terminal && progress.Pending != 0 ||
		job.Status == StateRunning && job.Attempt == 0 ||
		job.StartedAt != nil && job.StartedAt.Before(job.CreatedAt) ||
		job.CompletedAt != nil && job.CompletedAt.Before(job.UpdatedAt) {
		return ErrInvalidStoreResponse
	}
	switch job.Status {
	case StateQueued, StateRunning, StateSucceeded:
		if job.FailureCode != "" {
			return ErrInvalidStoreResponse
		}
	case StatePartialFailed, StateFailed:
		if job.FailureCode == "" {
			return ErrInvalidStoreResponse
		}
	case StateCancelled:
		if job.FailureCode != "cancelled" {
			return ErrInvalidStoreResponse
		}
	}
	return nil
}

func validateAttemptPage(attempts []Attempt, query AttemptQuery) error {
	if len(attempts) > query.Limit {
		return ErrInvalidStoreResponse
	}
	for index, attempt := range attempts {
		terminal := attempt.Status != AttemptRunning
		if attempt.Number == 0 || !validAttemptState(attempt.Status) || attempt.StartedAt.IsZero() ||
			attempt.LastHeartbeatAt.Before(attempt.StartedAt) || !attempt.LastHeartbeatAt.Before(attempt.LeaseExpiresAt) ||
			terminal != (attempt.CompletedAt != nil) ||
			attempt.CompletedAt != nil && attempt.CompletedAt.Before(attempt.LastHeartbeatAt) ||
			(attempt.FailureCode != "" && !stableIdentifierPattern.MatchString(attempt.FailureCode)) ||
			(query.AfterAttempt != nil && attempt.Number >= *query.AfterAttempt) ||
			(index > 0 && attempt.Number >= attempts[index-1].Number) {
			return ErrInvalidStoreResponse
		}
		switch attempt.Status {
		case AttemptRunning, AttemptSucceeded:
			if attempt.FailureCode != "" {
				return ErrInvalidStoreResponse
			}
		case AttemptPartialFailed, AttemptFailed:
			if attempt.FailureCode == "" {
				return ErrInvalidStoreResponse
			}
		case AttemptCancelled:
			if attempt.FailureCode != "cancelled" {
				return ErrInvalidStoreResponse
			}
		case AttemptLeaseExpired:
			if attempt.FailureCode != "lease_expired" {
				return ErrInvalidStoreResponse
			}
		}
	}
	return nil
}

func validateResultPage(results []ItemResult, query ResultQuery) error {
	if len(results) > query.Limit {
		return ErrInvalidStoreResponse
	}
	for index, result := range results {
		if result.Ordinal <= 0 || !validSafeText(result.ItemID, 256) ||
			(result.NodeID != nil && *result.NodeID == uuid.Nil) || !validResultState(result.Status) ||
			(result.FailureCode != "" && !stableIdentifierPattern.MatchString(result.FailureCode)) ||
			result.FailureCount < 0 ||
			(result.StartedAt != nil && (result.Status == ResultPending || !validUTCOutputTime(*result.StartedAt) ||
				result.CompletedAt != nil && result.StartedAt.After(*result.CompletedAt))) ||
			(query.AfterOrdinal != nil && result.Ordinal <= *query.AfterOrdinal) ||
			(index > 0 && result.Ordinal <= results[index-1].Ordinal) {
			return ErrInvalidStoreResponse
		}
		switch result.Status {
		case ResultPending:
			if result.Attempt != 0 || result.Sequence != 0 || result.FailureCode != "" || result.CompletedAt != nil {
				return ErrInvalidStoreResponse
			}
		case ResultSucceeded:
			if result.Attempt == 0 || result.Sequence == 0 || result.FailureCode != "" ||
				result.CompletedAt == nil || !validUTCOutputTime(*result.CompletedAt) {
				return ErrInvalidStoreResponse
			}
		case ResultFailed:
			if result.Attempt == 0 || result.FailureCode == "" ||
				result.CompletedAt == nil || !validUTCOutputTime(*result.CompletedAt) {
				return ErrInvalidStoreResponse
			}
		case ResultCancelled:
			if result.FailureCode != "cancelled" || result.CompletedAt == nil ||
				!validUTCOutputTime(*result.CompletedAt) {
				return ErrInvalidStoreResponse
			}
		}
	}
	return nil
}

func validateReceiptPage(receipts []SettlementReceipt, query ReceiptQuery) error {
	if len(receipts) > query.Limit {
		return ErrInvalidStoreResponse
	}
	for index, receipt := range receipts {
		if receipt.Ordinal <= 0 || receipt.Attempt == 0 || !validSafeText(receipt.ItemID, 256) ||
			(receipt.NodeID != nil && *receipt.NodeID == uuid.Nil) ||
			(receipt.Status != ResultSucceeded && receipt.Status != ResultFailed) ||
			(receipt.FailureCode != "" && !stableIdentifierPattern.MatchString(receipt.FailureCode)) ||
			(receipt.Source != "worker" && receipt.Source != "system") || !validUTCOutputTime(receipt.ReportedAt) ||
			(query.AfterAttempt != nil && (receipt.Attempt > *query.AfterAttempt ||
				receipt.Attempt == *query.AfterAttempt && receipt.Ordinal <= *query.AfterOrdinal)) {
			return ErrInvalidStoreResponse
		}
		if index > 0 && (receipt.Attempt > receipts[index-1].Attempt ||
			receipt.Attempt == receipts[index-1].Attempt && receipt.Ordinal <= receipts[index-1].Ordinal) {
			return ErrInvalidStoreResponse
		}
		if receipt.Status == ResultSucceeded && (receipt.Sequence == 0 || receipt.FailureCode != "") ||
			receipt.Status == ResultFailed && receipt.FailureCode == "" {
			return ErrInvalidStoreResponse
		}
	}
	return nil
}

func validateDeadLetterPage(letters []DeadLetter, query DeadLetterQuery) error {
	if len(letters) > query.Limit {
		return ErrInvalidStoreResponse
	}
	for index, letter := range letters {
		if letter.Attempt == 0 || !stableIdentifierPattern.MatchString(letter.ReasonCode) ||
			letter.FailedItemCount < 1 || (letter.Source != "worker" && letter.Source != "lease_expiry") ||
			!validUTCOutputTime(letter.CreatedAt) ||
			(query.AfterAttempt != nil && letter.Attempt >= *query.AfterAttempt) ||
			(index > 0 && letter.Attempt >= letters[index-1].Attempt) {
			return ErrInvalidStoreResponse
		}
	}
	return nil
}

func cloneUUID(value *uuid.UUID) *uuid.UUID {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
