module github.com/cdnca/cdnca/libs/themepack

go 1.27.0

toolchain go1.27.3

require (
	github.com/cdnca/cdnca/libs/edgeconfig v0.0.0
	golang.org/x/net v0.41.0
)

replace github.com/cdnca/cdnca/libs/edgeconfig => ../edgeconfig
