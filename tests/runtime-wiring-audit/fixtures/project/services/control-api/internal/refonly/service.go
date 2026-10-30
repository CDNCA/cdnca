package refonly

type Service struct{}

func NewService() *Service { return &Service{} }

func Describe() string { return "reference-only" }
