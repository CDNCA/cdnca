package pluginwebhook

import "errors"

var (
	ErrInvalidInput             = errors.New("invalid plugin webhook input")
	ErrInvalidConfig            = errors.New("invalid plugin webhook configuration")
	ErrInvalidSecret            = errors.New("invalid plugin webhook secret")
	ErrInvalidSignature         = errors.New("invalid plugin webhook signature")
	ErrSignatureExpired         = errors.New("plugin webhook signature timestamp outside tolerance")
	ErrTargetForbidden          = errors.New("plugin webhook target is forbidden")
	ErrTargetResolution         = errors.New("plugin webhook target resolution failed")
	ErrNoDelivery               = errors.New("no plugin webhook delivery available")
	ErrDeadLetterMissing        = errors.New("plugin webhook dead letter not found")
	ErrTenantScopeDenied        = errors.New("plugin webhook tenant scope denied")
	ErrProducerNotFound         = errors.New("plugin webhook producer subscription not found")
	ErrProducerPermissionDenied = errors.New("plugin webhook producer actor permission denied")
	ErrProducerState            = errors.New("plugin webhook producer state conflict")
	ErrProducerUnavailable      = errors.New("plugin webhook producer unavailable")
)
