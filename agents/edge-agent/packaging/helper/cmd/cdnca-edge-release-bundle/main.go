// Command cdnca-edge-release-bundle prepares the manifest v2 signing data for
// an Edge Agent release and, given an externally produced Ed25519 signature,
// assembles the canonical cdnca-edge-release-bundle/v1 that the root
// packaging helper installs. It never reads or generates a private key.
//
//	prepare  --release-dir DIR --release-sequence N --output-dir NEW_DIR
//	finalize --prepared-dir DIR --signature FILE --public-key PEM [--download-base-url URL]
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/cdnca/cdnca/agents/edge-agent/packaging/helper"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	result, err := dispatch(arguments)
	if err != nil {
		fmt.Fprintln(stderr, "cdnca-edge-release-bundle:", err)
		return 1
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintln(stderr, "cdnca-edge-release-bundle:", err)
		return 1
	}
	fmt.Fprintln(stdout, string(encoded))
	return 0
}

func dispatch(arguments []string) (any, error) {
	if len(arguments) == 0 {
		return nil, errors.New("expected prepare or finalize")
	}
	flags := flag.NewFlagSet(arguments[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	switch arguments[0] {
	case "prepare":
		releaseDir := flags.String("release-dir", "", "release-build output directory")
		sequence := flags.String("release-sequence", "", "positive, strictly increasing publication sequence")
		outputDir := flags.String("output-dir", "", "new directory for the signing data")
		if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 {
			return nil, errors.New("invalid prepare arguments")
		}
		value, err := strconv.ParseUint(*sequence, 10, 64)
		if err != nil || strconv.FormatUint(value, 10) != *sequence {
			return nil, errors.New("release sequence must be a canonical positive integer")
		}
		return helper.PrepareReleaseBundle(helper.PrepareOptions{ReleaseDir: *releaseDir, ReleaseSequence: value, OutputDir: *outputDir})
	case "finalize":
		preparedDir := flags.String("prepared-dir", "", "directory written by prepare")
		signature := flags.String("signature", "", "external Ed25519 signature over manifest.signing-data")
		publicKey := flags.String("public-key", "", "release public key PEM (package-signing.pem)")
		baseURL := flags.String("download-base-url", "", "immutable download origin, e.g. https://auth.cdnca.com/downloads")
		native := flags.String("native", "", "signed native node package of the same version (cdnca-edge-agent.tar.gz); makes a v2 bundle")
		if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 {
			return nil, errors.New("invalid finalize arguments")
		}
		return helper.FinalizeReleaseBundle(helper.FinalizeOptions{
			PreparedDir: *preparedDir, SignaturePath: *signature, PublicKeyPath: *publicKey, DownloadBaseURL: *baseURL, NativePackagePath: *native,
		})
	default:
		return nil, errors.New("expected prepare or finalize")
	}
}
