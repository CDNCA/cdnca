package main

import (
	"context"
	"errors"
	"net/http"
	"sync"

	"fixture/services/control-api/internal/asyncworker"
	"fixture/services/control-api/internal/database"
	"fixture/services/control-api/internal/fallibledep"
	"fixture/services/control-api/internal/generateddefault"
	"fixture/services/control-api/internal/loadedfactory"
	"fixture/services/control-api/internal/neverstarted"
	"fixture/services/control-api/internal/nildep"
	"fixture/services/control-api/internal/nilfactory"
	"fixture/services/control-api/internal/noopdep"
	"fixture/services/control-api/internal/proofok"
	"fixture/services/control-api/internal/refonly"
	"fixture/services/control-api/internal/samea"
	"fixture/services/control-api/internal/sameb"
	"fixture/services/control-api/internal/syncworker"
	"fixture/services/control-api/internal/wrongmount"
)

func main() {
	_ = database.Migrate(context.Background(), nil, "up")
	_ = run(nil)
}

func run(pool any) http.Handler {
	_ = noopdep.NewService(noopdep.NewNoop())
	_ = nildep.NewService(nil)
	missingFactory := missingDependency
	_ = nilfactory.NewService(missingFactory())
	_ = generateddefault.NewService(generatedDependency())
	dependency, _ := openFallibleDependency(false)
	_ = fallibledep.NewService(dependency)
	_ = loadedfactory.Load()
	_ = neverstarted.NewWorker()
	_ = refonly.Describe()
	deadBranchRuntimeReference()
	deadClosureRuntimeReference()
	deadCentralRouterReference()
	aliasRuntimeReferences()
	_ = wrongmount.NewHandler()
	synchronous := syncworker.NewWorker()
	_ = synchronous.Run(context.Background())
	ctx, cancel := context.WithCancel(context.Background())
	var background sync.WaitGroup
	worker := asyncworker.NewWorker()
	background.Add(1)
	go func() {
		defer background.Done()
		_ = worker.Run(ctx)
	}()
	cancel()
	background.Wait()
	service := samea.NewService(pool)
	proof := proofok.NewHandler(pool)
	mux := http.NewServeMux()
	mux.Handle("/v1/same-a", service.Handler())
	mux.Handle("/v1/proof", proof.Handler())
	return mux
}

func deadBranchRuntimeReference() {
	if false {
		_ = sameb.NewService()
	}
}

func deadClosureRuntimeReference() {
	unused := func() {
		_ = sameb.NewService()
	}
	_ = unused
}

func missingDependency() nilfactory.Dependency { return nil }

func generatedDependency() generateddefault.Dependency {
	return generateddefault.NewGeneratedMock()
}

func openFallibleDependency(fail bool) (fallibledep.Dependency, error) {
	if fail {
		return nil, errors.New("unavailable")
	}
	return fallibledep.Real{}, nil
}
