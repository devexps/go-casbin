package biz

import (
	v1 "github.com/devexps/go-casbin/api/gen/go/casbin_service/v1"
	"github.com/devexps/go-casbin/casbin_service/v2/internal/data"
	"github.com/devexps/go-micro/v2/log"
	"golang.org/x/net/context"
)

// PolicyUseCase interface.
type PolicyUseCase interface {
	LoadPolicy(ctx context.Context) error
	SavePolicy(ctx context.Context) error

	AddNamedPolicy(ctx context.Context, pType string, params []string) (bool, error)
	RemoveNamedPolicy(ctx context.Context, pType string, params []string) (bool, error)
	RemoveFilteredNamedPolicy(ctx context.Context, pType string, index int32, values []string) (bool, error)
	GetNamedPolicy(ctx context.Context, pType string) (*v1.Array2DReply, error)
	GetFilteredNamedPolicy(ctx context.Context, pType string, index int32, values []string) (*v1.Array2DReply, error)

	AddNamedGroupingPolicy(ctx context.Context, pType string, params []string) (bool, error)
	RemoveNamedGroupingPolicy(ctx context.Context, pType string, params []string) (bool, error)
	RemoveFilteredNamedGroupingPolicy(ctx context.Context, pType string, index int32, values []string) (bool, error)
	GetNamedGroupingPolicy(ctx context.Context, pType string) (*v1.Array2DReply, error)
	GetFilteredNamedGroupingPolicy(ctx context.Context, pType string, index int32, values []string) (*v1.Array2DReply, error)
}

type policyUseCase struct {
	log  *log.Helper
	repo data.CasbinRepo
}

// NewPolicyUseCase new policy use case.
func NewPolicyUseCase(logger log.Logger, repo data.CasbinRepo) PolicyUseCase {
	l := log.NewHelper(log.With(logger, "module", "casbin_servie/usecase/policy"))
	return &policyUseCase{
		log:  l,
		repo: repo,
	}
}

// LoadPolicy .
func (u *policyUseCase) LoadPolicy(ctx context.Context) error {
	enforcer, err := u.repo.GetEnforcer(ctx)
	if err != nil {
		return err
	}
	if err = enforcer.LoadPolicy(); err != nil {
		return v1.ErrorLoadPolicyFailed("load policy failed: %v", err.Error())
	}
	return nil
}

// SavePolicy .
func (u *policyUseCase) SavePolicy(ctx context.Context) error {
	enforcer, err := u.repo.GetEnforcer(ctx)
	if err != nil {
		return err
	}
	if err = enforcer.SavePolicy(); err != nil {
		return v1.ErrorSavePolicyFailed("save policy failed: %v", err.Error())
	}
	return nil
}

// AddNamedPolicy .
func (u *policyUseCase) AddNamedPolicy(ctx context.Context, pType string, params []string) (bool, error) {
	enforcer, err := u.repo.GetEnforcer(ctx)
	if err != nil {
		return false, err
	}
	b, err := enforcer.AddNamedPolicy(pType, params)
	if err != nil {
		return false, v1.ErrorAddNamedPolicyFailed("add named policy failed: %v", err.Error())
	}
	return b, nil
}

// RemoveNamedPolicy .
func (u *policyUseCase) RemoveNamedPolicy(ctx context.Context, pType string, params []string) (bool, error) {
	enforcer, err := u.repo.GetEnforcer(ctx)
	if err != nil {
		return false, err
	}
	b, err := enforcer.RemoveNamedPolicy(pType, params)
	if err != nil {
		return false, v1.ErrorRemoveNamedPolicyFailed("remove named policy failed: %v", err.Error())
	}
	return b, nil
}

// RemoveFilteredNamedPolicy .
func (u *policyUseCase) RemoveFilteredNamedPolicy(ctx context.Context, pType string, index int32, values []string) (bool, error) {
	enforcer, err := u.repo.GetEnforcer(ctx)
	if err != nil {
		return false, err
	}
	b, err := enforcer.RemoveFilteredNamedPolicy(pType, int(index), values...)
	if err != nil {
		return false, v1.ErrorRemoveFilteredNamedPolicyFailed("remove filtered policy failed: %v", err.Error())
	}
	return b, nil
}

// GetNamedPolicy .
func (u *policyUseCase) GetNamedPolicy(ctx context.Context, pType string) (*v1.Array2DReply, error) {
	enforcer, err := u.repo.GetEnforcer(ctx)
	if err != nil {
		return nil, err
	}
	return wrapPlainPolicy(enforcer.GetNamedPolicy(pType)), nil
}

// GetFilteredNamedPolicy .
func (u *policyUseCase) GetFilteredNamedPolicy(ctx context.Context, pType string, index int32, values []string) (*v1.Array2DReply, error) {
	enforcer, err := u.repo.GetEnforcer(ctx)
	if err != nil {
		return nil, err
	}
	return wrapPlainPolicy(enforcer.GetFilteredNamedPolicy(pType, int(index), values...)), nil
}

// AddNamedGroupingPolicy .
func (u *policyUseCase) AddNamedGroupingPolicy(ctx context.Context, pType string, params []string) (bool, error) {
	enforcer, err := u.repo.GetEnforcer(ctx)
	if err != nil {
		return false, err
	}
	b, err := enforcer.AddNamedGroupingPolicy(pType, params)
	if err != nil {
		return false, v1.ErrorAddNamedGroupingPolicyFailed("add named grouping policy failed: %v", err.Error())
	}
	return b, nil
}

// RemoveNamedGroupingPolicy .
func (u *policyUseCase) RemoveNamedGroupingPolicy(ctx context.Context, pType string, params []string) (bool, error) {
	enforcer, err := u.repo.GetEnforcer(ctx)
	if err != nil {
		return false, err
	}
	b, err := enforcer.RemoveNamedGroupingPolicy(pType, params)
	if err != nil {
		return false, v1.ErrorRemoveNamedGroupingPolicyFailed("remove named grouping policy failed: %v", err.Error())
	}
	return b, nil
}

// RemoveFilteredNamedGroupingPolicy .
func (u *policyUseCase) RemoveFilteredNamedGroupingPolicy(ctx context.Context, pType string, index int32, values []string) (bool, error) {
	enforcer, err := u.repo.GetEnforcer(ctx)
	if err != nil {
		return false, err
	}
	b, err := enforcer.RemoveFilteredNamedGroupingPolicy(pType, int(index), values...)
	if err != nil {
		return false, v1.ErrorRemoveFilteredNamedGroupingPolicyFailed("remove filtered named grouping policy failed: %v", err.Error())
	}
	return b, nil
}

// GetNamedGroupingPolicy .
func (u *policyUseCase) GetNamedGroupingPolicy(ctx context.Context, pType string) (*v1.Array2DReply, error) {
	enforcer, err := u.repo.GetEnforcer(ctx)
	if err != nil {
		return nil, err
	}
	return wrapPlainPolicy(enforcer.GetNamedGroupingPolicy(pType)), nil
}

// GetFilteredNamedGroupingPolicy .
func (u *policyUseCase) GetFilteredNamedGroupingPolicy(ctx context.Context, pType string, index int32, values []string) (*v1.Array2DReply, error) {
	enforcer, err := u.repo.GetEnforcer(ctx)
	if err != nil {
		return nil, err
	}
	return wrapPlainPolicy(enforcer.GetFilteredNamedGroupingPolicy(pType, int(index), values...)), nil
}

func wrapPlainPolicy(policy [][]string) *v1.Array2DReply {
	if len(policy) == 0 {
		return &v1.Array2DReply{}
	}
	policyReply := &v1.Array2DReply{}
	policyReply.D2 = make([]*v1.Array2DReplyD, len(policy))
	for e := range policy {
		policyReply.D2[e] = &v1.Array2DReplyD{D1: policy[e]}
	}
	return policyReply
}
