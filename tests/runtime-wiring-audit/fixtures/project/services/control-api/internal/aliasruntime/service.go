package aliasruntime

type Service struct{}

func NewDirect() *Service        { return &Service{} }
func NewTransactional() *Service { return &Service{} }
func NewAsync() *Service         { return &Service{} }
func NewVarAlias() *Service      { return &Service{} }
