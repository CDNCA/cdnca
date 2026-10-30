package main

import (
	"fmt"
	"strconv"

	"github.com/cdnca/cdnca/libs/edgeconfig"
)

// edgeLazyCertificateCacheMaxEnv sets ssl_certificate_cache max= on the
// nodes' lazy default servers (site runtime v7): parsed certificates each
// worker keeps, ≈4 KiB each for P-256. Unset or empty keeps the default.
const edgeLazyCertificateCacheMaxEnv = "CDNCA_EDGE_LAZY_CERTIFICATE_CACHE_MAX"

func loadEdgeLazyCertificateCacheMax(lookup func(string) (string, bool)) (int64, error) {
	raw, present := lookup(edgeLazyCertificateCacheMaxEnv)
	if !present || raw == "" {
		return edgeconfig.DefaultLazyCertificateCacheMax, nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || strconv.FormatInt(value, 10) != raw || (edgeconfig.SiteRuntimeLazyCertificates{CacheMax: value}).Validate() != nil {
		return 0, fmt.Errorf("%s must be an integer 1..%d", edgeLazyCertificateCacheMaxEnv, edgeconfig.MaxLazyCertificateCacheMax)
	}
	return value, nil
}
