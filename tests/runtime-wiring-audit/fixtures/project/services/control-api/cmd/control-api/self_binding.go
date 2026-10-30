package main

type selfBinding struct{}

func (selfBinding) Next() selfBinding { return selfBinding{} }

func deadSelfBinding() {
	value := selfBinding{}
	value = value.Next()
	_ = value
}
