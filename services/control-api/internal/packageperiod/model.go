package packageperiod

import "errors"

var (
	ErrInvalidTerms    = errors.New("invalid package validity terms")
	ErrInvalidCycle    = errors.New("invalid package quota cycle")
	ErrNoActiveCycle   = errors.New("package has no active quota cycle")
	ErrInvalidState    = errors.New("invalid package service state")
	ErrInvalidFactor   = errors.New("invalid traffic factor")
	ErrTrafficOverflow = errors.New("weighted traffic overflows uint64")
	ErrInvalidSnapshot = errors.New("invalid package cycle snapshot")
)

type Duration string

const (
	DurationMonth   Duration = "month"
	DurationQuarter Duration = "quarter"
	DurationYear    Duration = "year"
)

type CycleKind string

const (
	CycleDaily         CycleKind = "daily"
	CycleMonthly       CycleKind = "monthly"
	CycleCustomDays    CycleKind = "custom_days"
	MaxCustomCycleDays           = uint32(366)
)

type CyclePolicy struct {
	Kind       CycleKind
	CustomDays uint32
}
