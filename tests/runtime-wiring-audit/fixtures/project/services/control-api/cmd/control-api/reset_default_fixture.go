package main

import "fixture/services/control-api/internal/resetdefault"

func init() {
	_ = resetdefault.NewClient(nil)
}
