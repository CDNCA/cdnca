//go:build integration

package edgeautopublish

import "context"

// PackageExpiryWatcherNewFulfillment exposes the fulfillment cursor to the
// external integration test.
func PackageExpiryWatcherNewFulfillment(ctx context.Context, watcher *PackageExpiryWatcher) (bool, error) {
	return watcher.newFulfillment(ctx)
}
