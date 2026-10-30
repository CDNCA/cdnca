package main

// closePoolAfterStop cancels the run context, then closes the pool. pgxpool
// Close blocks until every borrowed connection is released; background loops
// that keep a connection (LISTEN) release it only when the context ends, so
// closing first on an error return leaves the process hung with its
// listeners open (market-pool-fix, same chain in market-service).
func closePoolAfterStop(stop func(), pool interface{ Close() }) {
	stop()
	pool.Close()
}
