package nodecertlifecycle

import "time"

const (
	CertificateUsable     = "usable"
	CertificateNearExpiry = "near_expiry"
	CertificatePending    = "pending"
	CertificateExpired    = "expired"
)

type CertificatePolicy struct {
	maximumClockSkew time.Duration
	renewBefore      time.Duration
}

type CertificateDecision struct {
	ConnectionAllowed bool
	RenewalRequired   bool
	Reason            string
}

func NewCertificatePolicy(maximumClockSkew, renewBefore time.Duration) (CertificatePolicy, error) {
	if maximumClockSkew < 0 || maximumClockSkew > 10*time.Minute || renewBefore <= maximumClockSkew || renewBefore > 30*24*time.Hour {
		return CertificatePolicy{}, ErrInvalidInput
	}
	return CertificatePolicy{maximumClockSkew: maximumClockSkew, renewBefore: renewBefore}, nil
}

func (policy CertificatePolicy) Evaluate(notBefore, notAfter, now time.Time) CertificateDecision {
	if notBefore.IsZero() || notAfter.IsZero() || !notBefore.Before(notAfter) || now.IsZero() {
		return CertificateDecision{Reason: CertificatePending}
	}
	now = now.UTC()
	if now.Add(policy.maximumClockSkew).Before(notBefore.UTC()) {
		return CertificateDecision{Reason: CertificatePending}
	}
	renewal := !now.Add(policy.renewBefore).Before(notAfter.UTC())
	if !now.Add(-policy.maximumClockSkew).Before(notAfter.UTC()) {
		return CertificateDecision{RenewalRequired: true, Reason: CertificateExpired}
	}
	if renewal {
		return CertificateDecision{ConnectionAllowed: true, RenewalRequired: true, Reason: CertificateNearExpiry}
	}
	return CertificateDecision{ConnectionAllowed: true, Reason: CertificateUsable}
}
