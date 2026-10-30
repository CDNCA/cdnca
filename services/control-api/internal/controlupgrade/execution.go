package controlupgrade

import (
	"context"

	"github.com/cdnca/cdnca/libs/entitlement"
)

func IssueCommandExecution(ctx context.Context, encodedCommandGrant []byte,
	commandGrantKeys *entitlement.KeyRing, options entitlement.UpgradeCommandGrantVerifyOptions,
	controlSigner, edgeSigner entitlement.Signer) ([]byte, error) {
	return entitlement.IssueCommandExecution(ctx, encodedCommandGrant, commandGrantKeys, options,
		controlSigner, edgeSigner)
}

// IssueCachedCommandExecution signs an execution whose download URL points at
// the control plane artifact cache instead of the license origin, with the
// current download policy for that URL (nil: none).
func IssueCachedCommandExecution(ctx context.Context, encodedCommandGrant []byte,
	commandGrantKeys *entitlement.KeyRing, options entitlement.UpgradeCommandGrantVerifyOptions,
	controlSigner, edgeSigner entitlement.Signer, downloadURL string, policy *entitlement.UpgradeDownloadPolicy) ([]byte, error) {
	return entitlement.IssueCommandExecutionWithDownloadPolicy(ctx, encodedCommandGrant, commandGrantKeys, options,
		controlSigner, edgeSigner, downloadURL, policy)
}
