package cachetask

import (
	"context"
	"encoding/hex"
	"errors"
	"time"
)

var (
	ErrCarrierActiveRevision  = errors.New("cache carrier active revision changed")
	ErrCarrierReceiptMismatch = errors.New("cache carrier receipt mismatch")
)

type TaskExecutor interface {
	Execute(context.Context, Task) (Result, error)
}

type Carrier struct {
	executor TaskExecutor
	resolver SiteResolver
}

type CarrierReceipt struct {
	SchemaVersion         int       `json:"schema_version"`
	TaskID                string    `json:"task_id"`
	OperationID           string    `json:"operation_id"`
	TenantID              string    `json:"tenant_id"`
	SiteID                string    `json:"site_id"`
	ConfigVersionID       string    `json:"config_version_id"`
	ConfigRevision        uint64    `json:"config_revision"`
	DeliveryAttempt       int       `json:"delivery_attempt"`
	State                 TaskState `json:"state"`
	ResultDigest          string    `json:"result_digest"`
	Progress              Progress  `json:"progress"`
	CompletedAt           time.Time `json:"completed_at"`
	Replayed              bool      `json:"replayed"`
	ActiveConfigUnchanged bool      `json:"active_config_unchanged"`
}

func NewCarrier(executor TaskExecutor, resolver SiteResolver) (*Carrier, error) {
	if executor == nil || resolver == nil {
		return nil, ErrInvalidTask
	}
	return &Carrier{executor: executor, resolver: resolver}, nil
}

func (carrier *Carrier) Execute(ctx context.Context, task Task) (Result, error) {
	result, _, err := carrier.execute(ctx, task)
	return result, err
}

func (carrier *Carrier) ExecuteReceipt(ctx context.Context, task Task) (CarrierReceipt, error) {
	_, receipt, err := carrier.execute(ctx, task)
	return receipt, err
}

func (carrier *Carrier) execute(ctx context.Context, task Task) (Result, CarrierReceipt, error) {
	if ctx == nil || !carrierTaskIdentityValid(task) {
		return Result{}, CarrierReceipt{}, ErrInvalidTask
	}
	before, err := carrier.resolve(ctx, task)
	if err != nil {
		return Result{}, CarrierReceipt{}, err
	}
	result, err := carrier.executor.Execute(ctx, task)
	if err != nil {
		return Result{}, CarrierReceipt{}, err
	}
	after, err := carrier.resolve(ctx, task)
	if err != nil || !equalSiteBinding(siteBindingFromContext(before), siteBindingFromContext(after)) {
		return Result{}, CarrierReceipt{}, ErrCarrierActiveRevision
	}
	if err := validateCarrierResult(task, result); err != nil {
		return Result{}, CarrierReceipt{}, err
	}
	receipt := CarrierReceipt{
		SchemaVersion: SchemaVersion, TaskID: result.TaskID, OperationID: result.OperationID,
		TenantID: result.TenantID, SiteID: result.SiteID,
		ConfigVersionID: result.ConfigVersionID, ConfigRevision: result.ConfigRevision,
		DeliveryAttempt: result.DeliveryAttempt, State: result.State, ResultDigest: result.Digest,
		Progress: result.Progress, CompletedAt: result.CompletedAt, Replayed: result.Replayed,
		ActiveConfigUnchanged: true,
	}
	return result, receipt, nil
}

func (carrier *Carrier) resolve(ctx context.Context, task Task) (SiteContext, error) {
	site, err := carrier.resolver.ResolveSite(
		ctx, task.TenantID, task.SiteID, task.ConfigVersionID, task.ConfigRevision,
	)
	if err != nil {
		return SiteContext{}, err
	}
	normalized, valid := normalizeSiteContext(site)
	if !valid || normalized.TenantID != task.TenantID || normalized.SiteID != task.SiteID ||
		normalized.ConfigVersionID != task.ConfigVersionID || normalized.ConfigRevision != task.ConfigRevision {
		return SiteContext{}, ErrCarrierActiveRevision
	}
	return normalized, nil
}

func carrierTaskIdentityValid(task Task) bool {
	return task.SchemaVersion == SchemaVersion && idPattern.MatchString(task.TaskID) &&
		idPattern.MatchString(task.OperationID) && idPattern.MatchString(task.TenantID) &&
		idPattern.MatchString(task.SiteID) && idPattern.MatchString(task.ConfigVersionID) &&
		task.ConfigRevision > 0 && task.DeliveryAttempt > 0
}

func validateCarrierResult(task Task, result Result) error {
	if result.SchemaVersion != SchemaVersion || result.TaskID != task.TaskID ||
		result.OperationID != task.OperationID || result.TenantID != task.TenantID ||
		result.SiteID != task.SiteID || result.Scope != task.Scope ||
		result.ConfigVersionID != task.ConfigVersionID || result.ConfigRevision != task.ConfigRevision ||
		result.DeliveryAttempt != task.DeliveryAttempt || result.Attempt < 1 || result.CompletedAt.IsZero() ||
		len(result.Digest) != 64 {
		return ErrCarrierReceiptMismatch
	}
	if decoded, err := hex.DecodeString(result.Digest); err != nil || len(decoded) != 32 {
		return ErrCarrierReceiptMismatch
	}
	progress := Progress{Total: len(result.Items)}
	for index, item := range result.Items {
		if item.Index != index || item.Attempts < 1 || item.CompletedAt.IsZero() {
			return ErrCarrierReceiptMismatch
		}
		switch item.Status {
		case ItemSuccess:
			progress.Succeeded++
		case ItemSkipped:
			progress.Skipped++
		case ItemFailed:
			progress.Failed++
		default:
			return ErrCarrierReceiptMismatch
		}
		progress.Completed++
		progress.Bytes += item.Bytes
	}
	if progress != result.Progress {
		return ErrCarrierReceiptMismatch
	}
	switch result.State {
	case StateSucceeded:
		if progress.Failed != 0 {
			return ErrCarrierReceiptMismatch
		}
	case StatePartialFailed:
		if progress.Failed == 0 || progress.Failed == progress.Total {
			return ErrCarrierReceiptMismatch
		}
	case StateFailed:
		if progress.Total == 0 || progress.Failed != progress.Total {
			return ErrCarrierReceiptMismatch
		}
	case StateCancelled:
		if progress.Total != 0 && progress.Failed != progress.Total {
			return ErrCarrierReceiptMismatch
		}
	default:
		return ErrCarrierReceiptMismatch
	}
	return nil
}
