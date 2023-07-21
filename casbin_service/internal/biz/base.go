package biz

import (
	v1 "github.com/devexps/go-casbin/api/gen/go/casbin_service/v1"
	"github.com/devexps/go-casbin/casbin_service/v2/internal/data"
	"github.com/devexps/go-micro/v2/log"
	"golang.org/x/net/context"
)

// BasicUseCase interface.
type BasicUseCase interface {
	GetAllNamedSubjects(ctx context.Context, pType string) (*v1.ArrayReply, error)
	GetAllNamedObjects(ctx context.Context, pType string) (*v1.ArrayReply, error)
	GetAllNamedActions(ctx context.Context, pType string) (*v1.ArrayReply, error)
	GetAllNamedRoles(ctx context.Context, pType string) (*v1.ArrayReply, error)
	HasNamedPolicy(ctx context.Context, pType string, params []string) (bool, error)
	HasNamedGroupingPolicy(ctx context.Context, pType string, params []string) (bool, error)
}

type basicUseCase struct {
	log  *log.Helper
	repo data.CasbinRepo
}

// NewBasicUseCase new an Enforce use case.
func NewBasicUseCase(logger log.Logger, repo data.CasbinRepo) BasicUseCase {
	l := log.NewHelper(log.With(logger, "module", "casbin_servie/usecase/basic"))
	return &basicUseCase{
		log:  l,
		repo: repo,
	}
}

// GetAllNamedSubjects .
func (u *basicUseCase) GetAllNamedSubjects(ctx context.Context, pType string) (*v1.ArrayReply, error) {
	enforcer, err := u.repo.GetEnforcer(ctx)
	if err != nil {
		return nil, err
	}
	return &v1.ArrayReply{Array: enforcer.GetAllNamedSubjects(pType)}, nil
}

// GetAllNamedObjects .
func (u *basicUseCase) GetAllNamedObjects(ctx context.Context, pType string) (*v1.ArrayReply, error) {
	enforcer, err := u.repo.GetEnforcer(ctx)
	if err != nil {
		return nil, err
	}
	return &v1.ArrayReply{Array: enforcer.GetAllNamedObjects(pType)}, nil
}

// GetAllNamedActions .
func (u *basicUseCase) GetAllNamedActions(ctx context.Context, pType string) (*v1.ArrayReply, error) {
	enforcer, err := u.repo.GetEnforcer(ctx)
	if err != nil {
		return nil, err
	}
	return &v1.ArrayReply{Array: enforcer.GetAllNamedActions(pType)}, nil
}

// GetAllNamedRoles .
func (u *basicUseCase) GetAllNamedRoles(ctx context.Context, pType string) (*v1.ArrayReply, error) {
	enforcer, err := u.repo.GetEnforcer(ctx)
	if err != nil {
		return nil, err
	}
	return &v1.ArrayReply{Array: enforcer.GetAllNamedRoles(pType)}, nil
}

// HasNamedPolicy .
func (u *basicUseCase) HasNamedPolicy(ctx context.Context, pType string, params []string) (bool, error) {
	enforcer, err := u.repo.GetEnforcer(ctx)
	if err != nil {
		return false, err
	}
	return enforcer.HasNamedPolicy(pType, params), nil
}

// HasNamedGroupingPolicy .
func (u *basicUseCase) HasNamedGroupingPolicy(ctx context.Context, pType string, params []string) (bool, error) {
	enforcer, err := u.repo.GetEnforcer(ctx)
	if err != nil {
		return false, err
	}
	return enforcer.HasNamedGroupingPolicy(pType, params), nil
}
