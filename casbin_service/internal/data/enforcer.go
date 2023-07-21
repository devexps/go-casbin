package data

import (
	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/devexps/go-casbin/api/gen/go/common/conf"
	"github.com/devexps/go-casbin/casbin_service/v2/internal/data/ent"
	"github.com/devexps/go-micro/v2/log"
)

// NewEnforcer .
func NewEnforcer(logger log.Logger, cfg *conf.Bootstrap, client *ent.Client) casbin.IEnforcer {
	l := log.NewHelper(log.With(logger, "module", "casbin_service/data/enforcer"))

	a, err := NewAdapter(client)
	if err != nil {
		l.Fatal("new casbin adapter error: ", err)
	}
	m, err := model.NewModelFromFile(cfg.Data.Casbin.GetModelPath())
	if err != nil {
		l.Fatal("new model from file error: ", err)
	}
	enforcer, err := casbin.NewSyncedEnforcer(m, a)
	if err != nil {
		l.Fatal("new enforcer error: ", err)
	}
	return enforcer
}
