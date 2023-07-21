package data

import (
	"context"
	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/devexps/go-casbin/casbin_service/v2/internal/data/ent"
	"github.com/devexps/go-casbin/casbin_service/v2/internal/data/ent/casbinrule"
	"github.com/devexps/go-casbin/casbin_service/v2/internal/data/ent/predicate"
	"github.com/pkg/errors"
	"strings"
)

type Adapter interface {
}

type adapter struct {
	client *ent.Client
	ctx    context.Context
}

type Option func(a *adapter) error

// NewAdapter .
func NewAdapter(client *ent.Client, options ...Option) (Adapter, error) {
	a := &adapter{
		client: client,
		ctx:    context.Background(),
	}
	for _, option := range options {
		if err := option(a); err != nil {
			return nil, err
		}
	}
	return a, nil
}

// LoadPolicy loads all policy rules from the storage.
func (a *adapter) LoadPolicy(model model.Model) error {
	policies, err := a.client.CasbinRule.Query().Order(ent.Asc("id")).All(a.ctx)
	if err != nil {
		return err
	}
	for _, policy := range policies {
		loadPolicyLine(policy, model)
	}
	return nil
}

// SavePolicy saves all policy rules to the storage.
func (a *adapter) SavePolicy(model model.Model) error {
	return a.WithTx(func(tx *ent.Tx) error {
		if _, err := tx.CasbinRule.Delete().Exec(a.ctx); err != nil {
			return err
		}
		lines := make([]*ent.CasbinRuleCreate, 0)

		for ptype, ast := range model["p"] {
			for _, policy := range ast.Policy {
				line := a.savePolicyLine(tx, ptype, policy)
				lines = append(lines, line)
			}
		}
		for ptype, ast := range model["g"] {
			for _, policy := range ast.Policy {
				line := a.savePolicyLine(tx, ptype, policy)
				lines = append(lines, line)
			}
		}
		_, err := tx.CasbinRule.CreateBulk(lines...).Save(a.ctx)
		return err
	})
}

// AddPolicy adds a policy rule to the storage.
// This is part of the Auto-Save feature.
func (a *adapter) AddPolicy(sec string, ptype string, rule []string) error {
	return a.WithTx(func(tx *ent.Tx) error {
		_, err := a.savePolicyLine(tx, ptype, rule).Save(a.ctx)
		return err
	})
}

// RemovePolicy removes a policy rule from the storage.
// This is part of the Auto-Save feature.
func (a *adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	return a.WithTx(func(tx *ent.Tx) error {
		instance := a.toInstance(ptype, rule)
		_, err := tx.CasbinRule.Delete().Where(
			casbinrule.PtypeEQ(instance.Ptype),
			casbinrule.V0EQ(instance.V0),
			casbinrule.V1EQ(instance.V1),
			casbinrule.V2EQ(instance.V2),
			casbinrule.V3EQ(instance.V3),
			casbinrule.V4EQ(instance.V4),
			casbinrule.V5EQ(instance.V5),
		).Exec(a.ctx)
		return err
	})
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
// This is part of the Auto-Save feature.
func (a *adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	return a.WithTx(func(tx *ent.Tx) error {
		cond := make([]predicate.CasbinRule, 0)
		cond = append(cond, casbinrule.PtypeEQ(ptype))
		if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) && len(fieldValues[0-fieldIndex]) > 0 {
			cond = append(cond, casbinrule.V0EQ(fieldValues[0-fieldIndex]))
		}
		if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) && len(fieldValues[1-fieldIndex]) > 0 {
			cond = append(cond, casbinrule.V1EQ(fieldValues[1-fieldIndex]))
		}
		if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) && len(fieldValues[2-fieldIndex]) > 0 {
			cond = append(cond, casbinrule.V2EQ(fieldValues[2-fieldIndex]))
		}
		if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) && len(fieldValues[3-fieldIndex]) > 0 {
			cond = append(cond, casbinrule.V3EQ(fieldValues[3-fieldIndex]))
		}
		if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) && len(fieldValues[4-fieldIndex]) > 0 {
			cond = append(cond, casbinrule.V4EQ(fieldValues[4-fieldIndex]))
		}
		if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) && len(fieldValues[5-fieldIndex]) > 0 {
			cond = append(cond, casbinrule.V5EQ(fieldValues[5-fieldIndex]))
		}
		_, err := tx.CasbinRule.Delete().Where(
			cond...,
		).Exec(a.ctx)
		return err
	})
}

// AddPolicies adds policy rules to the storage.
// This is part of the Auto-Save feature.
func (a *adapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	return a.WithTx(func(tx *ent.Tx) error {
		return a.createPolicies(tx, ptype, rules)
	})
}

// RemovePolicies removes policy rules from the storage.
// This is part of the Auto-Save feature.
func (a *adapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	return a.WithTx(func(tx *ent.Tx) error {
		for _, rule := range rules {
			instance := a.toInstance(ptype, rule)
			if _, err := tx.CasbinRule.Delete().Where(
				casbinrule.PtypeEQ(instance.Ptype),
				casbinrule.V0EQ(instance.V0),
				casbinrule.V1EQ(instance.V1),
				casbinrule.V2EQ(instance.V2),
				casbinrule.V3EQ(instance.V3),
				casbinrule.V4EQ(instance.V4),
				casbinrule.V5EQ(instance.V5),
			).Exec(a.ctx); err != nil {
				return err
			}
		}
		return nil
	})
}

// UpdatePolicy updates a policy rule from storage.
// This is part of the Auto-Save feature.
func (a *adapter) UpdatePolicy(sec string, ptype string, oldRule, newPolicy []string) error {
	return a.WithTx(func(tx *ent.Tx) error {
		rule := a.toInstance(ptype, oldRule)
		line := tx.CasbinRule.Update().Where(
			casbinrule.PtypeEQ(rule.Ptype),
			casbinrule.V0EQ(rule.V0),
			casbinrule.V1EQ(rule.V1),
			casbinrule.V2EQ(rule.V2),
			casbinrule.V3EQ(rule.V3),
			casbinrule.V4EQ(rule.V4),
			casbinrule.V5EQ(rule.V5),
		)
		rule = a.toInstance(ptype, newPolicy)
		line.SetV0(rule.V0)
		line.SetV1(rule.V1)
		line.SetV2(rule.V2)
		line.SetV3(rule.V3)
		line.SetV4(rule.V4)
		line.SetV5(rule.V5)
		_, err := line.Save(a.ctx)
		return err
	})
}

// UpdatePolicies updates some policy rules to storage, like db, redis.
func (a *adapter) UpdatePolicies(sec string, ptype string, oldRules, newRules [][]string) error {
	return a.WithTx(func(tx *ent.Tx) error {
		for _, policy := range oldRules {
			rule := a.toInstance(ptype, policy)
			if _, err := tx.CasbinRule.Delete().Where(
				casbinrule.PtypeEQ(rule.Ptype),
				casbinrule.V0EQ(rule.V0),
				casbinrule.V1EQ(rule.V1),
				casbinrule.V2EQ(rule.V2),
				casbinrule.V3EQ(rule.V3),
				casbinrule.V4EQ(rule.V4),
				casbinrule.V5EQ(rule.V5),
			).Exec(a.ctx); err != nil {
				return err
			}
		}
		lines := make([]*ent.CasbinRuleCreate, 0)
		for _, policy := range newRules {
			lines = append(lines, a.savePolicyLine(tx, ptype, policy))
		}
		if _, err := tx.CasbinRule.CreateBulk(lines...).Save(a.ctx); err != nil {
			return err
		}
		return nil
	})
}

func (a *adapter) WithTx(fn func(tx *ent.Tx) error) error {
	tx, err := a.client.Tx(a.ctx)
	if err != nil {
		return err
	}
	defer func() {
		if v := recover(); v != nil {
			_ = tx.Rollback()
			panic(v)
		}
	}()
	if err := fn(tx); err != nil {
		if rerr := tx.Rollback(); rerr != nil {
			err = errors.Wrapf(err, "rolling back transaction: %v", rerr)
		}
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.Wrapf(err, "committing transaction: %v", err)
	}
	return nil
}

func (a *adapter) toInstance(ptype string, rule []string) *ent.CasbinRule {
	instance := &ent.CasbinRule{}

	instance.Ptype = ptype

	if len(rule) > 0 {
		instance.V0 = rule[0]
	}
	if len(rule) > 1 {
		instance.V1 = rule[1]
	}
	if len(rule) > 2 {
		instance.V2 = rule[2]
	}
	if len(rule) > 3 {
		instance.V3 = rule[3]
	}
	if len(rule) > 4 {
		instance.V4 = rule[4]
	}
	if len(rule) > 5 {
		instance.V5 = rule[5]
	}
	return instance
}

func (a *adapter) savePolicyLine(tx *ent.Tx, ptype string, rule []string) *ent.CasbinRuleCreate {
	line := tx.CasbinRule.Create()

	line.SetPtype(ptype)
	if len(rule) > 0 {
		line.SetV0(rule[0])
	}
	if len(rule) > 1 {
		line.SetV1(rule[1])
	}
	if len(rule) > 2 {
		line.SetV2(rule[2])
	}
	if len(rule) > 3 {
		line.SetV3(rule[3])
	}
	if len(rule) > 4 {
		line.SetV4(rule[4])
	}
	if len(rule) > 5 {
		line.SetV5(rule[5])
	}
	return line
}

func (a *adapter) createPolicies(tx *ent.Tx, ptype string, policies [][]string) error {
	lines := make([]*ent.CasbinRuleCreate, 0)
	for _, policy := range policies {
		lines = append(lines, a.savePolicyLine(tx, ptype, policy))
	}
	if _, err := tx.CasbinRule.CreateBulk(lines...).Save(a.ctx); err != nil {
		return err
	}
	return nil
}

func loadPolicyLine(line *ent.CasbinRule, model model.Model) {
	var p = []string{line.Ptype,
		line.V0, line.V1, line.V2, line.V3, line.V4, line.V5}

	var lineText string
	if line.V5 != "" {
		lineText = strings.Join(p, ", ")
	} else if line.V4 != "" {
		lineText = strings.Join(p[:6], ", ")
	} else if line.V3 != "" {
		lineText = strings.Join(p[:5], ", ")
	} else if line.V2 != "" {
		lineText = strings.Join(p[:4], ", ")
	} else if line.V1 != "" {
		lineText = strings.Join(p[:3], ", ")
	} else if line.V0 != "" {
		lineText = strings.Join(p[:2], ", ")
	}
	persist.LoadPolicyLine(lineText, model)
}

func CasbinRuleToStringArray(rule *ent.CasbinRule) []string {
	arr := make([]string, 0)
	if rule.V0 != "" {
		arr = append(arr, rule.V0)
	}
	if rule.V1 != "" {
		arr = append(arr, rule.V1)
	}
	if rule.V2 != "" {
		arr = append(arr, rule.V2)
	}
	if rule.V3 != "" {
		arr = append(arr, rule.V3)
	}
	if rule.V4 != "" {
		arr = append(arr, rule.V4)
	}
	if rule.V5 != "" {
		arr = append(arr, rule.V5)
	}
	return arr
}
