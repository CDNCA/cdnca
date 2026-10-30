module github.com/cdnca/management-web

go 1.27.0

toolchain go1.27.3

require (
	github.com/cdnca/cdnca/libs/mtlstunnel v0.0.0
	github.com/gorilla/websocket v1.5.3
)

replace github.com/cdnca/cdnca/libs/mtlstunnel => ../../libs/mtlstunnel
