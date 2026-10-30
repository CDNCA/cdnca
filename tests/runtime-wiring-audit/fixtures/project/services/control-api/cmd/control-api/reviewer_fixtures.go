package main

import (
	"fixture/services/control-api/internal/safedefault"
	"fixture/services/control-api/internal/shadowdefault"
)

func init() {
	_ = safedefault.NewClient(nil)
	_ = shadowdefault.NewShortClient(nil)
	_ = shadowdefault.NewIfInitClient(nil)
}
