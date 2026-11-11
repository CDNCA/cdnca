package accountregistration

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/cdnca/cdnca/services/control-api/internal/systemusersettings"
)

// 邮箱验证和手机验证可以同时打开，打开几项就必须带几项
// 各自通道的证明，全部通过才注册。证明逐个校验并消费；证明按幂等键可重放，
// 所以一项失败后沿用同一幂等键重试，已通过的那项不必重新验证。

// RequiredProofChannels lists, in a fixed order (email, sms), the channels
// whose verified proof a registration must carry under the policy.
func RequiredProofChannels(policy systemusersettings.PublicSettings) []string {
	var channels []string
	if policy.EmailVerificationRequired {
		channels = append(channels, VerificationEmail)
	}
	if policy.PhoneVerificationRequired {
		channels = append(channels, VerificationSMS)
	}
	return channels
}

// proofReference is the reference proving channel: the per-channel one, else
// (only one proof needed) the legacy single reference.
func proofReference(input RegisterInput, channel string, total int) string {
	if reference := input.ProofReferences[channel]; reference != "" {
		return reference
	}
	if total == 1 {
		return input.ProofReference
	}
	return ""
}

// consumeProofs verifies and consumes one proof per channel and returns the
// evidence identities joined in channel order (one channel: exactly the
// single evidence id, so single-channel request digests are unchanged).
func consumeProofs(
	ctx context.Context,
	authority ProofAuthority,
	input RegisterInput,
	channels []string,
	subjectDigest [32]byte,
	now time.Time,
) (string, error) {
	evidence := make([]string, 0, len(channels))
	for _, channel := range channels {
		destination := input.Email
		if channel == VerificationSMS {
			destination = input.Phone
		}
		reference := proofReference(input, channel, len(channels))
		if reference == "" || destination == "" {
			return "", ErrProofInvalid
		}
		proof, err := authority.VerifyAndConsume(ctx, RegistrationProofRequest{
			Reference: reference, Channel: channel, Destination: destination,
			Source: input.Source, IdempotencyKey: input.IdempotencyKey, SubjectDigest: subjectDigest,
		})
		if err != nil {
			if errors.Is(err, ErrProofInvalid) {
				return "", ErrProofInvalid
			}
			return "", fmt.Errorf("%w: %v", ErrProofUnavailable, err)
		}
		if !validRegistrationProof(proof, channel, destination, now) {
			return "", ErrProofInvalid
		}
		evidence = append(evidence, proof.EvidenceID.String())
	}
	return strings.Join(evidence, ","), nil
}

// validProofReferences checks the legacy and per-channel references; at
// least one must be present.
func validProofReferences(input RegisterInput) bool {
	count := 0
	check := func(reference string) bool {
		if reference == "" {
			return true
		}
		count++
		return len(reference) >= 22 && len(reference) <= 4096 && registrationProofPattern.MatchString(reference)
	}
	if !check(input.ProofReference) {
		return false
	}
	for channel, reference := range input.ProofReferences {
		if channel != VerificationEmail && channel != VerificationSMS || !check(reference) {
			return false
		}
	}
	return count > 0
}
