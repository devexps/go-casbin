package data

import (
	"context"
	_ "embed"
	"github.com/casbin/casbin/v2"
	v1 "github.com/devexps/go-casbin/api/gen/go/casbin_service/v1"
	"github.com/devexps/go-micro/v2/log"
)

// CasbinRepo interface.
type CasbinRepo interface {
	GetEnforcer(ctx context.Context) (casbin.IEnforcer, error)
}

type casbinRepo struct {
	data     *Data
	log      *log.Helper
	enforcer casbin.IEnforcer
}

// NewCasbinRepo .
func NewCasbinRepo(data *Data, logger log.Logger, enforcer casbin.IEnforcer) CasbinRepo {
	l := log.NewHelper(log.With(logger, "module", "casbin_service/data/casbin"))
	return &casbinRepo{
		data:     data,
		log:      l,
		enforcer: enforcer,
	}
}

// GetEnforcer .
func (c *casbinRepo) GetEnforcer(ctx context.Context) (casbin.IEnforcer, error) {
	if c.enforcer == nil {
		return nil, v1.ErrorEnforceInvalid("enforcer is nil")
	}
	return c.enforcer, nil
}
