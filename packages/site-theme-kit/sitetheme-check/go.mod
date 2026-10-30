module cdnca/packages/site-theme-kit/sitetheme-check

go 1.27.0

toolchain go1.27.3

require (
	github.com/cdnca/cdnca/libs/sitetheme v0.0.0
	github.com/cdnca/cdnca/libs/themepack v0.0.0
)

require (
	github.com/cdnca/cdnca/libs/edgeconfig v0.0.0 // indirect
	golang.org/x/net v0.41.0 // indirect
)

replace (
	github.com/cdnca/cdnca/libs/edgeconfig => ../../../libs/edgeconfig
	github.com/cdnca/cdnca/libs/sitetheme => ../../../libs/sitetheme
	github.com/cdnca/cdnca/libs/themepack => ../../../libs/themepack
)
