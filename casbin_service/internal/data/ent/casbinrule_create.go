// Code generated by ent, DO NOT EDIT.

package ent

import (
	"context"
	"errors"
	"fmt"

	"entgo.io/ent/dialect/sql"
	"entgo.io/ent/dialect/sql/sqlgraph"
	"entgo.io/ent/schema/field"
	"github.com/devexps/go-casbin/casbin_service/v2/internal/data/ent/casbinrule"
)

// CasbinRuleCreate is the builder for creating a CasbinRule entity.
type CasbinRuleCreate struct {
	config
	mutation *CasbinRuleMutation
	hooks    []Hook
	conflict []sql.ConflictOption
}

// SetPtype sets the "Ptype" field.
func (crc *CasbinRuleCreate) SetPtype(s string) *CasbinRuleCreate {
	crc.mutation.SetPtype(s)
	return crc
}

// SetNillablePtype sets the "Ptype" field if the given value is not nil.
func (crc *CasbinRuleCreate) SetNillablePtype(s *string) *CasbinRuleCreate {
	if s != nil {
		crc.SetPtype(*s)
	}
	return crc
}

// SetV0 sets the "V0" field.
func (crc *CasbinRuleCreate) SetV0(s string) *CasbinRuleCreate {
	crc.mutation.SetV0(s)
	return crc
}

// SetNillableV0 sets the "V0" field if the given value is not nil.
func (crc *CasbinRuleCreate) SetNillableV0(s *string) *CasbinRuleCreate {
	if s != nil {
		crc.SetV0(*s)
	}
	return crc
}

// SetV1 sets the "V1" field.
func (crc *CasbinRuleCreate) SetV1(s string) *CasbinRuleCreate {
	crc.mutation.SetV1(s)
	return crc
}

// SetNillableV1 sets the "V1" field if the given value is not nil.
func (crc *CasbinRuleCreate) SetNillableV1(s *string) *CasbinRuleCreate {
	if s != nil {
		crc.SetV1(*s)
	}
	return crc
}

// SetV2 sets the "V2" field.
func (crc *CasbinRuleCreate) SetV2(s string) *CasbinRuleCreate {
	crc.mutation.SetV2(s)
	return crc
}

// SetNillableV2 sets the "V2" field if the given value is not nil.
func (crc *CasbinRuleCreate) SetNillableV2(s *string) *CasbinRuleCreate {
	if s != nil {
		crc.SetV2(*s)
	}
	return crc
}

// SetV3 sets the "V3" field.
func (crc *CasbinRuleCreate) SetV3(s string) *CasbinRuleCreate {
	crc.mutation.SetV3(s)
	return crc
}

// SetNillableV3 sets the "V3" field if the given value is not nil.
func (crc *CasbinRuleCreate) SetNillableV3(s *string) *CasbinRuleCreate {
	if s != nil {
		crc.SetV3(*s)
	}
	return crc
}

// SetV4 sets the "V4" field.
func (crc *CasbinRuleCreate) SetV4(s string) *CasbinRuleCreate {
	crc.mutation.SetV4(s)
	return crc
}

// SetNillableV4 sets the "V4" field if the given value is not nil.
func (crc *CasbinRuleCreate) SetNillableV4(s *string) *CasbinRuleCreate {
	if s != nil {
		crc.SetV4(*s)
	}
	return crc
}

// SetV5 sets the "V5" field.
func (crc *CasbinRuleCreate) SetV5(s string) *CasbinRuleCreate {
	crc.mutation.SetV5(s)
	return crc
}

// SetNillableV5 sets the "V5" field if the given value is not nil.
func (crc *CasbinRuleCreate) SetNillableV5(s *string) *CasbinRuleCreate {
	if s != nil {
		crc.SetV5(*s)
	}
	return crc
}

// Mutation returns the CasbinRuleMutation object of the builder.
func (crc *CasbinRuleCreate) Mutation() *CasbinRuleMutation {
	return crc.mutation
}

// Save creates the CasbinRule in the database.
func (crc *CasbinRuleCreate) Save(ctx context.Context) (*CasbinRule, error) {
	var (
		err  error
		node *CasbinRule
	)
	crc.defaults()
	if len(crc.hooks) == 0 {
		if err = crc.check(); err != nil {
			return nil, err
		}
		node, err = crc.sqlSave(ctx)
	} else {
		var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
			mutation, ok := m.(*CasbinRuleMutation)
			if !ok {
				return nil, fmt.Errorf("unexpected mutation type %T", m)
			}
			if err = crc.check(); err != nil {
				return nil, err
			}
			crc.mutation = mutation
			if node, err = crc.sqlSave(ctx); err != nil {
				return nil, err
			}
			mutation.id = &node.ID
			mutation.done = true
			return node, err
		})
		for i := len(crc.hooks) - 1; i >= 0; i-- {
			if crc.hooks[i] == nil {
				return nil, fmt.Errorf("ent: uninitialized hook (forgotten import ent/runtime?)")
			}
			mut = crc.hooks[i](mut)
		}
		v, err := mut.Mutate(ctx, crc.mutation)
		if err != nil {
			return nil, err
		}
		nv, ok := v.(*CasbinRule)
		if !ok {
			return nil, fmt.Errorf("unexpected node type %T returned from CasbinRuleMutation", v)
		}
		node = nv
	}
	return node, err
}

// SaveX calls Save and panics if Save returns an error.
func (crc *CasbinRuleCreate) SaveX(ctx context.Context) *CasbinRule {
	v, err := crc.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (crc *CasbinRuleCreate) Exec(ctx context.Context) error {
	_, err := crc.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (crc *CasbinRuleCreate) ExecX(ctx context.Context) {
	if err := crc.Exec(ctx); err != nil {
		panic(err)
	}
}

// defaults sets the default values of the builder before save.
func (crc *CasbinRuleCreate) defaults() {
	if _, ok := crc.mutation.Ptype(); !ok {
		v := casbinrule.DefaultPtype
		crc.mutation.SetPtype(v)
	}
	if _, ok := crc.mutation.V0(); !ok {
		v := casbinrule.DefaultV0
		crc.mutation.SetV0(v)
	}
	if _, ok := crc.mutation.V1(); !ok {
		v := casbinrule.DefaultV1
		crc.mutation.SetV1(v)
	}
	if _, ok := crc.mutation.V2(); !ok {
		v := casbinrule.DefaultV2
		crc.mutation.SetV2(v)
	}
	if _, ok := crc.mutation.V3(); !ok {
		v := casbinrule.DefaultV3
		crc.mutation.SetV3(v)
	}
	if _, ok := crc.mutation.V4(); !ok {
		v := casbinrule.DefaultV4
		crc.mutation.SetV4(v)
	}
	if _, ok := crc.mutation.V5(); !ok {
		v := casbinrule.DefaultV5
		crc.mutation.SetV5(v)
	}
}

// check runs all checks and user-defined validators on the builder.
func (crc *CasbinRuleCreate) check() error {
	if _, ok := crc.mutation.Ptype(); !ok {
		return &ValidationError{Name: "Ptype", err: errors.New(`ent: missing required field "CasbinRule.Ptype"`)}
	}
	if _, ok := crc.mutation.V0(); !ok {
		return &ValidationError{Name: "V0", err: errors.New(`ent: missing required field "CasbinRule.V0"`)}
	}
	if _, ok := crc.mutation.V1(); !ok {
		return &ValidationError{Name: "V1", err: errors.New(`ent: missing required field "CasbinRule.V1"`)}
	}
	if _, ok := crc.mutation.V2(); !ok {
		return &ValidationError{Name: "V2", err: errors.New(`ent: missing required field "CasbinRule.V2"`)}
	}
	if _, ok := crc.mutation.V3(); !ok {
		return &ValidationError{Name: "V3", err: errors.New(`ent: missing required field "CasbinRule.V3"`)}
	}
	if _, ok := crc.mutation.V4(); !ok {
		return &ValidationError{Name: "V4", err: errors.New(`ent: missing required field "CasbinRule.V4"`)}
	}
	if _, ok := crc.mutation.V5(); !ok {
		return &ValidationError{Name: "V5", err: errors.New(`ent: missing required field "CasbinRule.V5"`)}
	}
	return nil
}

func (crc *CasbinRuleCreate) sqlSave(ctx context.Context) (*CasbinRule, error) {
	_node, _spec := crc.createSpec()
	if err := sqlgraph.CreateNode(ctx, crc.driver, _spec); err != nil {
		if sqlgraph.IsConstraintError(err) {
			err = &ConstraintError{msg: err.Error(), wrap: err}
		}
		return nil, err
	}
	id := _spec.ID.Value.(int64)
	_node.ID = int(id)
	return _node, nil
}

func (crc *CasbinRuleCreate) createSpec() (*CasbinRule, *sqlgraph.CreateSpec) {
	var (
		_node = &CasbinRule{config: crc.config}
		_spec = &sqlgraph.CreateSpec{
			Table: casbinrule.Table,
			ID: &sqlgraph.FieldSpec{
				Type:   field.TypeInt,
				Column: casbinrule.FieldID,
			},
		}
	)
	_spec.OnConflict = crc.conflict
	if value, ok := crc.mutation.Ptype(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: casbinrule.FieldPtype,
		})
		_node.Ptype = value
	}
	if value, ok := crc.mutation.V0(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: casbinrule.FieldV0,
		})
		_node.V0 = value
	}
	if value, ok := crc.mutation.V1(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: casbinrule.FieldV1,
		})
		_node.V1 = value
	}
	if value, ok := crc.mutation.V2(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: casbinrule.FieldV2,
		})
		_node.V2 = value
	}
	if value, ok := crc.mutation.V3(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: casbinrule.FieldV3,
		})
		_node.V3 = value
	}
	if value, ok := crc.mutation.V4(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: casbinrule.FieldV4,
		})
		_node.V4 = value
	}
	if value, ok := crc.mutation.V5(); ok {
		_spec.Fields = append(_spec.Fields, &sqlgraph.FieldSpec{
			Type:   field.TypeString,
			Value:  value,
			Column: casbinrule.FieldV5,
		})
		_node.V5 = value
	}
	return _node, _spec
}

// OnConflict allows configuring the `ON CONFLICT` / `ON DUPLICATE KEY` clause
// of the `INSERT` statement. For example:
//
//	client.CasbinRule.Create().
//		SetPtype(v).
//		OnConflict(
//			// Update the row with the new values
//			// the was proposed for insertion.
//			sql.ResolveWithNewValues(),
//		).
//		// Override some of the fields with custom
//		// update values.
//		Update(func(u *ent.CasbinRuleUpsert) {
//			SetPtype(v+v).
//		}).
//		Exec(ctx)
//
func (crc *CasbinRuleCreate) OnConflict(opts ...sql.ConflictOption) *CasbinRuleUpsertOne {
	crc.conflict = opts
	return &CasbinRuleUpsertOne{
		create: crc,
	}
}

// OnConflictColumns calls `OnConflict` and configures the columns
// as conflict target. Using this option is equivalent to using:
//
//	client.CasbinRule.Create().
//		OnConflict(sql.ConflictColumns(columns...)).
//		Exec(ctx)
//
func (crc *CasbinRuleCreate) OnConflictColumns(columns ...string) *CasbinRuleUpsertOne {
	crc.conflict = append(crc.conflict, sql.ConflictColumns(columns...))
	return &CasbinRuleUpsertOne{
		create: crc,
	}
}

type (
	// CasbinRuleUpsertOne is the builder for "upsert"-ing
	//  one CasbinRule node.
	CasbinRuleUpsertOne struct {
		create *CasbinRuleCreate
	}

	// CasbinRuleUpsert is the "OnConflict" setter.
	CasbinRuleUpsert struct {
		*sql.UpdateSet
	}
)

// SetPtype sets the "Ptype" field.
func (u *CasbinRuleUpsert) SetPtype(v string) *CasbinRuleUpsert {
	u.Set(casbinrule.FieldPtype, v)
	return u
}

// UpdatePtype sets the "Ptype" field to the value that was provided on create.
func (u *CasbinRuleUpsert) UpdatePtype() *CasbinRuleUpsert {
	u.SetExcluded(casbinrule.FieldPtype)
	return u
}

// SetV0 sets the "V0" field.
func (u *CasbinRuleUpsert) SetV0(v string) *CasbinRuleUpsert {
	u.Set(casbinrule.FieldV0, v)
	return u
}

// UpdateV0 sets the "V0" field to the value that was provided on create.
func (u *CasbinRuleUpsert) UpdateV0() *CasbinRuleUpsert {
	u.SetExcluded(casbinrule.FieldV0)
	return u
}

// SetV1 sets the "V1" field.
func (u *CasbinRuleUpsert) SetV1(v string) *CasbinRuleUpsert {
	u.Set(casbinrule.FieldV1, v)
	return u
}

// UpdateV1 sets the "V1" field to the value that was provided on create.
func (u *CasbinRuleUpsert) UpdateV1() *CasbinRuleUpsert {
	u.SetExcluded(casbinrule.FieldV1)
	return u
}

// SetV2 sets the "V2" field.
func (u *CasbinRuleUpsert) SetV2(v string) *CasbinRuleUpsert {
	u.Set(casbinrule.FieldV2, v)
	return u
}

// UpdateV2 sets the "V2" field to the value that was provided on create.
func (u *CasbinRuleUpsert) UpdateV2() *CasbinRuleUpsert {
	u.SetExcluded(casbinrule.FieldV2)
	return u
}

// SetV3 sets the "V3" field.
func (u *CasbinRuleUpsert) SetV3(v string) *CasbinRuleUpsert {
	u.Set(casbinrule.FieldV3, v)
	return u
}

// UpdateV3 sets the "V3" field to the value that was provided on create.
func (u *CasbinRuleUpsert) UpdateV3() *CasbinRuleUpsert {
	u.SetExcluded(casbinrule.FieldV3)
	return u
}

// SetV4 sets the "V4" field.
func (u *CasbinRuleUpsert) SetV4(v string) *CasbinRuleUpsert {
	u.Set(casbinrule.FieldV4, v)
	return u
}

// UpdateV4 sets the "V4" field to the value that was provided on create.
func (u *CasbinRuleUpsert) UpdateV4() *CasbinRuleUpsert {
	u.SetExcluded(casbinrule.FieldV4)
	return u
}

// SetV5 sets the "V5" field.
func (u *CasbinRuleUpsert) SetV5(v string) *CasbinRuleUpsert {
	u.Set(casbinrule.FieldV5, v)
	return u
}

// UpdateV5 sets the "V5" field to the value that was provided on create.
func (u *CasbinRuleUpsert) UpdateV5() *CasbinRuleUpsert {
	u.SetExcluded(casbinrule.FieldV5)
	return u
}

// UpdateNewValues updates the mutable fields using the new values that were set on create.
// Using this option is equivalent to using:
//
//	client.CasbinRule.Create().
//		OnConflict(
//			sql.ResolveWithNewValues(),
//		).
//		Exec(ctx)
//
func (u *CasbinRuleUpsertOne) UpdateNewValues() *CasbinRuleUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithNewValues())
	return u
}

// Ignore sets each column to itself in case of conflict.
// Using this option is equivalent to using:
//
//  client.CasbinRule.Create().
//      OnConflict(sql.ResolveWithIgnore()).
//      Exec(ctx)
//
func (u *CasbinRuleUpsertOne) Ignore() *CasbinRuleUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithIgnore())
	return u
}

// DoNothing configures the conflict_action to `DO NOTHING`.
// Supported only by SQLite and PostgreSQL.
func (u *CasbinRuleUpsertOne) DoNothing() *CasbinRuleUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.DoNothing())
	return u
}

// Update allows overriding fields `UPDATE` values. See the CasbinRuleCreate.OnConflict
// documentation for more info.
func (u *CasbinRuleUpsertOne) Update(set func(*CasbinRuleUpsert)) *CasbinRuleUpsertOne {
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(update *sql.UpdateSet) {
		set(&CasbinRuleUpsert{UpdateSet: update})
	}))
	return u
}

// SetPtype sets the "Ptype" field.
func (u *CasbinRuleUpsertOne) SetPtype(v string) *CasbinRuleUpsertOne {
	return u.Update(func(s *CasbinRuleUpsert) {
		s.SetPtype(v)
	})
}

// UpdatePtype sets the "Ptype" field to the value that was provided on create.
func (u *CasbinRuleUpsertOne) UpdatePtype() *CasbinRuleUpsertOne {
	return u.Update(func(s *CasbinRuleUpsert) {
		s.UpdatePtype()
	})
}

// SetV0 sets the "V0" field.
func (u *CasbinRuleUpsertOne) SetV0(v string) *CasbinRuleUpsertOne {
	return u.Update(func(s *CasbinRuleUpsert) {
		s.SetV0(v)
	})
}

// UpdateV0 sets the "V0" field to the value that was provided on create.
func (u *CasbinRuleUpsertOne) UpdateV0() *CasbinRuleUpsertOne {
	return u.Update(func(s *CasbinRuleUpsert) {
		s.UpdateV0()
	})
}

// SetV1 sets the "V1" field.
func (u *CasbinRuleUpsertOne) SetV1(v string) *CasbinRuleUpsertOne {
	return u.Update(func(s *CasbinRuleUpsert) {
		s.SetV1(v)
	})
}

// UpdateV1 sets the "V1" field to the value that was provided on create.
func (u *CasbinRuleUpsertOne) UpdateV1() *CasbinRuleUpsertOne {
	return u.Update(func(s *CasbinRuleUpsert) {
		s.UpdateV1()
	})
}

// SetV2 sets the "V2" field.
func (u *CasbinRuleUpsertOne) SetV2(v string) *CasbinRuleUpsertOne {
	return u.Update(func(s *CasbinRuleUpsert) {
		s.SetV2(v)
	})
}

// UpdateV2 sets the "V2" field to the value that was provided on create.
func (u *CasbinRuleUpsertOne) UpdateV2() *CasbinRuleUpsertOne {
	return u.Update(func(s *CasbinRuleUpsert) {
		s.UpdateV2()
	})
}

// SetV3 sets the "V3" field.
func (u *CasbinRuleUpsertOne) SetV3(v string) *CasbinRuleUpsertOne {
	return u.Update(func(s *CasbinRuleUpsert) {
		s.SetV3(v)
	})
}

// UpdateV3 sets the "V3" field to the value that was provided on create.
func (u *CasbinRuleUpsertOne) UpdateV3() *CasbinRuleUpsertOne {
	return u.Update(func(s *CasbinRuleUpsert) {
		s.UpdateV3()
	})
}

// SetV4 sets the "V4" field.
func (u *CasbinRuleUpsertOne) SetV4(v string) *CasbinRuleUpsertOne {
	return u.Update(func(s *CasbinRuleUpsert) {
		s.SetV4(v)
	})
}

// UpdateV4 sets the "V4" field to the value that was provided on create.
func (u *CasbinRuleUpsertOne) UpdateV4() *CasbinRuleUpsertOne {
	return u.Update(func(s *CasbinRuleUpsert) {
		s.UpdateV4()
	})
}

// SetV5 sets the "V5" field.
func (u *CasbinRuleUpsertOne) SetV5(v string) *CasbinRuleUpsertOne {
	return u.Update(func(s *CasbinRuleUpsert) {
		s.SetV5(v)
	})
}

// UpdateV5 sets the "V5" field to the value that was provided on create.
func (u *CasbinRuleUpsertOne) UpdateV5() *CasbinRuleUpsertOne {
	return u.Update(func(s *CasbinRuleUpsert) {
		s.UpdateV5()
	})
}

// Exec executes the query.
func (u *CasbinRuleUpsertOne) Exec(ctx context.Context) error {
	if len(u.create.conflict) == 0 {
		return errors.New("ent: missing options for CasbinRuleCreate.OnConflict")
	}
	return u.create.Exec(ctx)
}

// ExecX is like Exec, but panics if an error occurs.
func (u *CasbinRuleUpsertOne) ExecX(ctx context.Context) {
	if err := u.create.Exec(ctx); err != nil {
		panic(err)
	}
}

// Exec executes the UPSERT query and returns the inserted/updated ID.
func (u *CasbinRuleUpsertOne) ID(ctx context.Context) (id int, err error) {
	node, err := u.create.Save(ctx)
	if err != nil {
		return id, err
	}
	return node.ID, nil
}

// IDX is like ID, but panics if an error occurs.
func (u *CasbinRuleUpsertOne) IDX(ctx context.Context) int {
	id, err := u.ID(ctx)
	if err != nil {
		panic(err)
	}
	return id
}

// CasbinRuleCreateBulk is the builder for creating many CasbinRule entities in bulk.
type CasbinRuleCreateBulk struct {
	config
	builders []*CasbinRuleCreate
	conflict []sql.ConflictOption
}

// Save creates the CasbinRule entities in the database.
func (crcb *CasbinRuleCreateBulk) Save(ctx context.Context) ([]*CasbinRule, error) {
	specs := make([]*sqlgraph.CreateSpec, len(crcb.builders))
	nodes := make([]*CasbinRule, len(crcb.builders))
	mutators := make([]Mutator, len(crcb.builders))
	for i := range crcb.builders {
		func(i int, root context.Context) {
			builder := crcb.builders[i]
			builder.defaults()
			var mut Mutator = MutateFunc(func(ctx context.Context, m Mutation) (Value, error) {
				mutation, ok := m.(*CasbinRuleMutation)
				if !ok {
					return nil, fmt.Errorf("unexpected mutation type %T", m)
				}
				if err := builder.check(); err != nil {
					return nil, err
				}
				builder.mutation = mutation
				nodes[i], specs[i] = builder.createSpec()
				var err error
				if i < len(mutators)-1 {
					_, err = mutators[i+1].Mutate(root, crcb.builders[i+1].mutation)
				} else {
					spec := &sqlgraph.BatchCreateSpec{Nodes: specs}
					spec.OnConflict = crcb.conflict
					// Invoke the actual operation on the latest mutation in the chain.
					if err = sqlgraph.BatchCreate(ctx, crcb.driver, spec); err != nil {
						if sqlgraph.IsConstraintError(err) {
							err = &ConstraintError{msg: err.Error(), wrap: err}
						}
					}
				}
				if err != nil {
					return nil, err
				}
				mutation.id = &nodes[i].ID
				if specs[i].ID.Value != nil {
					id := specs[i].ID.Value.(int64)
					nodes[i].ID = int(id)
				}
				mutation.done = true
				return nodes[i], nil
			})
			for i := len(builder.hooks) - 1; i >= 0; i-- {
				mut = builder.hooks[i](mut)
			}
			mutators[i] = mut
		}(i, ctx)
	}
	if len(mutators) > 0 {
		if _, err := mutators[0].Mutate(ctx, crcb.builders[0].mutation); err != nil {
			return nil, err
		}
	}
	return nodes, nil
}

// SaveX is like Save, but panics if an error occurs.
func (crcb *CasbinRuleCreateBulk) SaveX(ctx context.Context) []*CasbinRule {
	v, err := crcb.Save(ctx)
	if err != nil {
		panic(err)
	}
	return v
}

// Exec executes the query.
func (crcb *CasbinRuleCreateBulk) Exec(ctx context.Context) error {
	_, err := crcb.Save(ctx)
	return err
}

// ExecX is like Exec, but panics if an error occurs.
func (crcb *CasbinRuleCreateBulk) ExecX(ctx context.Context) {
	if err := crcb.Exec(ctx); err != nil {
		panic(err)
	}
}

// OnConflict allows configuring the `ON CONFLICT` / `ON DUPLICATE KEY` clause
// of the `INSERT` statement. For example:
//
//	client.CasbinRule.CreateBulk(builders...).
//		OnConflict(
//			// Update the row with the new values
//			// the was proposed for insertion.
//			sql.ResolveWithNewValues(),
//		).
//		// Override some of the fields with custom
//		// update values.
//		Update(func(u *ent.CasbinRuleUpsert) {
//			SetPtype(v+v).
//		}).
//		Exec(ctx)
//
func (crcb *CasbinRuleCreateBulk) OnConflict(opts ...sql.ConflictOption) *CasbinRuleUpsertBulk {
	crcb.conflict = opts
	return &CasbinRuleUpsertBulk{
		create: crcb,
	}
}

// OnConflictColumns calls `OnConflict` and configures the columns
// as conflict target. Using this option is equivalent to using:
//
//	client.CasbinRule.Create().
//		OnConflict(sql.ConflictColumns(columns...)).
//		Exec(ctx)
//
func (crcb *CasbinRuleCreateBulk) OnConflictColumns(columns ...string) *CasbinRuleUpsertBulk {
	crcb.conflict = append(crcb.conflict, sql.ConflictColumns(columns...))
	return &CasbinRuleUpsertBulk{
		create: crcb,
	}
}

// CasbinRuleUpsertBulk is the builder for "upsert"-ing
// a bulk of CasbinRule nodes.
type CasbinRuleUpsertBulk struct {
	create *CasbinRuleCreateBulk
}

// UpdateNewValues updates the mutable fields using the new values that
// were set on create. Using this option is equivalent to using:
//
//	client.CasbinRule.Create().
//		OnConflict(
//			sql.ResolveWithNewValues(),
//		).
//		Exec(ctx)
//
func (u *CasbinRuleUpsertBulk) UpdateNewValues() *CasbinRuleUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithNewValues())
	return u
}

// Ignore sets each column to itself in case of conflict.
// Using this option is equivalent to using:
//
//	client.CasbinRule.Create().
//		OnConflict(sql.ResolveWithIgnore()).
//		Exec(ctx)
//
func (u *CasbinRuleUpsertBulk) Ignore() *CasbinRuleUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWithIgnore())
	return u
}

// DoNothing configures the conflict_action to `DO NOTHING`.
// Supported only by SQLite and PostgreSQL.
func (u *CasbinRuleUpsertBulk) DoNothing() *CasbinRuleUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.DoNothing())
	return u
}

// Update allows overriding fields `UPDATE` values. See the CasbinRuleCreateBulk.OnConflict
// documentation for more info.
func (u *CasbinRuleUpsertBulk) Update(set func(*CasbinRuleUpsert)) *CasbinRuleUpsertBulk {
	u.create.conflict = append(u.create.conflict, sql.ResolveWith(func(update *sql.UpdateSet) {
		set(&CasbinRuleUpsert{UpdateSet: update})
	}))
	return u
}

// SetPtype sets the "Ptype" field.
func (u *CasbinRuleUpsertBulk) SetPtype(v string) *CasbinRuleUpsertBulk {
	return u.Update(func(s *CasbinRuleUpsert) {
		s.SetPtype(v)
	})
}

// UpdatePtype sets the "Ptype" field to the value that was provided on create.
func (u *CasbinRuleUpsertBulk) UpdatePtype() *CasbinRuleUpsertBulk {
	return u.Update(func(s *CasbinRuleUpsert) {
		s.UpdatePtype()
	})
}

// SetV0 sets the "V0" field.
func (u *CasbinRuleUpsertBulk) SetV0(v string) *CasbinRuleUpsertBulk {
	return u.Update(func(s *CasbinRuleUpsert) {
		s.SetV0(v)
	})
}

// UpdateV0 sets the "V0" field to the value that was provided on create.
func (u *CasbinRuleUpsertBulk) UpdateV0() *CasbinRuleUpsertBulk {
	return u.Update(func(s *CasbinRuleUpsert) {
		s.UpdateV0()
	})
}

// SetV1 sets the "V1" field.
func (u *CasbinRuleUpsertBulk) SetV1(v string) *CasbinRuleUpsertBulk {
	return u.Update(func(s *CasbinRuleUpsert) {
		s.SetV1(v)
	})
}

// UpdateV1 sets the "V1" field to the value that was provided on create.
func (u *CasbinRuleUpsertBulk) UpdateV1() *CasbinRuleUpsertBulk {
	return u.Update(func(s *CasbinRuleUpsert) {
		s.UpdateV1()
	})
}

// SetV2 sets the "V2" field.
func (u *CasbinRuleUpsertBulk) SetV2(v string) *CasbinRuleUpsertBulk {
	return u.Update(func(s *CasbinRuleUpsert) {
		s.SetV2(v)
	})
}

// UpdateV2 sets the "V2" field to the value that was provided on create.
func (u *CasbinRuleUpsertBulk) UpdateV2() *CasbinRuleUpsertBulk {
	return u.Update(func(s *CasbinRuleUpsert) {
		s.UpdateV2()
	})
}

// SetV3 sets the "V3" field.
func (u *CasbinRuleUpsertBulk) SetV3(v string) *CasbinRuleUpsertBulk {
	return u.Update(func(s *CasbinRuleUpsert) {
		s.SetV3(v)
	})
}

// UpdateV3 sets the "V3" field to the value that was provided on create.
func (u *CasbinRuleUpsertBulk) UpdateV3() *CasbinRuleUpsertBulk {
	return u.Update(func(s *CasbinRuleUpsert) {
		s.UpdateV3()
	})
}

// SetV4 sets the "V4" field.
func (u *CasbinRuleUpsertBulk) SetV4(v string) *CasbinRuleUpsertBulk {
	return u.Update(func(s *CasbinRuleUpsert) {
		s.SetV4(v)
	})
}

// UpdateV4 sets the "V4" field to the value that was provided on create.
func (u *CasbinRuleUpsertBulk) UpdateV4() *CasbinRuleUpsertBulk {
	return u.Update(func(s *CasbinRuleUpsert) {
		s.UpdateV4()
	})
}

// SetV5 sets the "V5" field.
func (u *CasbinRuleUpsertBulk) SetV5(v string) *CasbinRuleUpsertBulk {
	return u.Update(func(s *CasbinRuleUpsert) {
		s.SetV5(v)
	})
}

// UpdateV5 sets the "V5" field to the value that was provided on create.
func (u *CasbinRuleUpsertBulk) UpdateV5() *CasbinRuleUpsertBulk {
	return u.Update(func(s *CasbinRuleUpsert) {
		s.UpdateV5()
	})
}

// Exec executes the query.
func (u *CasbinRuleUpsertBulk) Exec(ctx context.Context) error {
	for i, b := range u.create.builders {
		if len(b.conflict) != 0 {
			return fmt.Errorf("ent: OnConflict was set for builder %d. Set it on the CasbinRuleCreateBulk instead", i)
		}
	}
	if len(u.create.conflict) == 0 {
		return errors.New("ent: missing options for CasbinRuleCreateBulk.OnConflict")
	}
	return u.create.Exec(ctx)
}

// ExecX is like Exec, but panics if an error occurs.
func (u *CasbinRuleUpsertBulk) ExecX(ctx context.Context) {
	if err := u.create.Exec(ctx); err != nil {
		panic(err)
	}
}
