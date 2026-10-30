package loadedfactory

type Service struct{}

func Load() *Service { return &Service{} }
