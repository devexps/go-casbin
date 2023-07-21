package biz

import (
	"context"
	"github.com/casbin/casbin/v2"
	v1 "github.com/devexps/go-casbin/api/gen/go/casbin_service/v1"
	"github.com/devexps/go-casbin/casbin_service/v2/internal/biz/abac"
	"github.com/devexps/go-casbin/casbin_service/v2/internal/data"
	"github.com/devexps/go-micro/v2/log"
	"strings"
)

// EnforceUseCase interface.
type EnforceUseCase interface {
	Enforce(ctx context.Context, params []string) (bool, error)
}

type enforceUseCase struct {
	log  *log.Helper
	repo data.CasbinRepo
}

// NewEnforceUseCase new an Enforce use case.
func NewEnforceUseCase(logger log.Logger, repo data.CasbinRepo) EnforceUseCase {
	l := log.NewHelper(log.With(logger, "module", "casbin_servie/usecase/enforce"))
	return &enforceUseCase{
		log:  l,
		repo: repo,
	}
}

// Enforce .
func (u *enforceUseCase) Enforce(ctx context.Context, params []string) (bool, error) {
	enforcer, err := u.repo.GetEnforcer(ctx)
	if err != nil {
		return false, err
	}
	var value interface{}
	values := make([]interface{}, 0, len(params))
	matcher := u.getMatcher(enforcer)

	for idx := range params {
		value, matcher = u.parseParam(params[idx], matcher)
		values = append(values, value)
	}
	res, err := enforcer.EnforceWithMatcher(matcher, values...)
	if err != nil {
		return false, v1.ErrorEnforceWithMatcherFailed(err.Error())
	}
	return res, nil
}

func (u *enforceUseCase) getMatcher(enforcer casbin.IEnforcer) string {
	return enforcer.GetModel()["m"]["m"].Value
}

func (u *enforceUseCase) parseParam(param string, matcher string) (interface{}, string) {
	if strings.HasPrefix(param, abac.Prefix) {
		attrList, err := abac.Resolve(param)
		if err != nil {
			u.log.Error("resolve ABAC failed: ", err.Error())
			return param, matcher
		}
		for k, v := range attrList.NameMap {
			old := "." + k
			if strings.Contains(matcher, old) {
				matcher = strings.Replace(matcher, old, "."+v, -1)
			}
		}
		return attrList, matcher
	}
	return param, matcher
}
