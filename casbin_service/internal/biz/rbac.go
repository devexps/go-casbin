package biz

import (
	"context"
	v1 "github.com/devexps/go-casbin/api/gen/go/casbin_service/v1"
	"github.com/devexps/go-casbin/casbin_service/v2/internal/data"
	"github.com/devexps/go-micro/v2/log"
)

// RBACUseCase interface.
type RBACUseCase interface {
	GetRolesForUser(ctx context.Context, user string) ([]string, error)
	GetImplicitRolesForUser(ctx context.Context, user string) ([]string, error)
	GetUsersForRole(ctx context.Context, role string) ([]string, error)
	HasRoleForUser(ctx context.Context, user, role string) (bool, error)
	AddRoleForUser(ctx context.Context, user, role string) (bool, error)
	DeleteRoleForUser(ctx context.Context, user, role string) (bool, error)
	DeleteRolesForUser(ctx context.Context, user string) (bool, error)
	DeleteUser(ctx context.Context, user string) (bool, error)
	DeleteRole(ctx context.Context, role string) (bool, error)
	GetPermissionsForUser(ctx context.Context, user string) (*v1.Array2DReply, error)
	GetImplicitPermissionsForUser(ctx context.Context, user string) (*v1.Array2DReply, error)
	DeletePermission(ctx context.Context, permissions []string) (bool, error)
	AddPermissionForUser(ctx context.Context, user string, permissions []string) (bool, error)
	DeletePermissionForUser(ctx context.Context, user string, permissions []string) (bool, error)
	DeletePermissionsForUser(ctx context.Context, user string) (bool, error)
	HasPermissionForUser(ctx context.Context, user string, permissions []string) (bool, error)
}

type rbacUseCase struct {
	log  *log.Helper
	repo data.CasbinRepo
}

// NewRBACUseCase new an Enforce use case.
func NewRBACUseCase(logger log.Logger, repo data.CasbinRepo) RBACUseCase {
	l := log.NewHelper(log.With(logger, "module", "casbin_servie/usecase/rbac"))
	return &rbacUseCase{
		log:  l,
		repo: repo,
	}
}

// GetRolesForUser .
func (u *rbacUseCase) GetRolesForUser(ctx context.Context, user string) ([]string, error) {
	enforcer, err := u.repo.GetEnforcer(ctx)
	if err != nil {
		return nil, err
	}
	rm := enforcer.GetModel()["g"]["g"].RM
	if rm == nil {
		return nil, v1.ErrorRoleManagerIsNil("role manager is nil")
	}
	res, err := rm.GetRoles(user)
	if err != nil {
		return nil, v1.ErrorGetUserRolesFailed("get user (%s) roles failed: %v", user, err.Error())
	}
	return res, nil
}

// GetImplicitRolesForUser .
func (u *rbacUseCase) GetImplicitRolesForUser(ctx context.Context, user string) ([]string, error) {
	enforcer, err := u.repo.GetEnforcer(ctx)
	if err != nil {
		return nil, err
	}
	res, err := enforcer.GetImplicitRolesForUser(user)
	if err != nil {
		return nil, v1.ErrorGetImplicitRolesForUserFailed("get implicit roles for user (%s) failed: %v", user, err.Error())
	}
	return res, nil
}

// GetUsersForRole .
func (u *rbacUseCase) GetUsersForRole(ctx context.Context, role string) ([]string, error) {
	enforcer, err := u.repo.GetEnforcer(ctx)
	if err != nil {
		return nil, err
	}
	rm := enforcer.GetModel()["g"]["g"].RM
	if rm == nil {
		return nil, v1.ErrorRoleManagerIsNil("role manager is nil")
	}
	res, err := rm.GetUsers(role)
	if err != nil {
		return nil, v1.ErrorGetUsersFailed("get users (%s) failed: %v", role, err.Error())
	}
	return res, nil
}

// HasRoleForUser .
func (u *rbacUseCase) HasRoleForUser(ctx context.Context, user, role string) (bool, error) {
	enforcer, err := u.repo.GetEnforcer(ctx)
	if err != nil {
		return false, err
	}
	roles, err := enforcer.GetRolesForUser(user)
	if err != nil {
		return false, v1.ErrorGetRolesForUserFailed("get roles for user (%s) failed: %v", user, err.Error())
	}
	for _, r := range roles {
		if r == role {
			return true, nil
		}
	}
	return false, nil
}

// AddRoleForUser .
func (u *rbacUseCase) AddRoleForUser(ctx context.Context, user, role string) (bool, error) {
	enforcer, err := u.repo.GetEnforcer(ctx)
	if err != nil {
		return false, err
	}
	ruleAdded, err := enforcer.AddGroupingPolicy(user, role)
	if err != nil {
		return false, v1.ErrorAddGroupingPolicyFailed("add grouping policy failed: %v", err.Error())
	}
	return ruleAdded, nil
}

// DeleteRoleForUser .
func (u *rbacUseCase) DeleteRoleForUser(ctx context.Context, user, role string) (bool, error) {
	enforcer, err := u.repo.GetEnforcer(ctx)
	if err != nil {
		return false, err
	}
	ruleRemoved, err := enforcer.RemoveGroupingPolicy(user, role)
	if err != nil {
		return false, v1.ErrorRemoveGroupingPolicyFailed("remove grouping policy failed: %v", err.Error())
	}
	return ruleRemoved, nil
}

// DeleteRolesForUser .
func (u *rbacUseCase) DeleteRolesForUser(ctx context.Context, user string) (bool, error) {
	enforcer, err := u.repo.GetEnforcer(ctx)
	if err != nil {
		return false, err
	}
	ruleRemoved, err := enforcer.RemoveFilteredGroupingPolicy(0, user)
	if err != nil {
		return false, v1.ErrorRemoveFilteredGroupingPolicyFailed("remove filtered grouping policy failed: %v", err.Error())
	}
	return ruleRemoved, nil
}

// DeleteUser .
func (u *rbacUseCase) DeleteUser(ctx context.Context, user string) (bool, error) {
	enforcer, err := u.repo.GetEnforcer(ctx)
	if err != nil {
		return false, err
	}
	userRemoved, err := enforcer.DeleteUser(user)
	if err != nil {
		return false, v1.ErrorDeleteUserFailed("delete user (%s) failed: %v", user, err.Error())
	}
	return userRemoved, nil
}

// DeleteRole .
func (u *rbacUseCase) DeleteRole(ctx context.Context, role string) (bool, error) {
	enforcer, err := u.repo.GetEnforcer(ctx)
	if err != nil {
		return false, err
	}
	roleRemoved, err := enforcer.DeleteRole(role)
	if err != nil {
		return false, v1.ErrorDeleteRoleFailed("delete role (%s) failed: %v", role, err.Error())
	}
	return roleRemoved, nil
}

// GetPermissionsForUser .
func (u *rbacUseCase) GetPermissionsForUser(ctx context.Context, user string) (*v1.Array2DReply, error) {
	enforcer, err := u.repo.GetEnforcer(ctx)
	if err != nil {
		return nil, err
	}
	return wrapPlainPolicy(enforcer.GetPermissionsForUser(user)), nil
}

// GetImplicitPermissionsForUser .
func (u *rbacUseCase) GetImplicitPermissionsForUser(ctx context.Context, user string) (*v1.Array2DReply, error) {
	enforcer, err := u.repo.GetEnforcer(ctx)
	if err != nil {
		return nil, err
	}
	res, err := enforcer.GetImplicitPermissionsForUser(user)
	u.log.Info(res)
	if err != nil {
		return nil, v1.ErrorGetImplicitPermissionsForUserFailed("get implicit permissions for user (%s) failed: %v", user, err.Error())
	}
	return wrapPlainPolicy(res), nil
}

// DeletePermission .
func (u *rbacUseCase) DeletePermission(ctx context.Context, permissions []string) (bool, error) {
	enforcer, err := u.repo.GetEnforcer(ctx)
	if err != nil {
		return false, err
	}
	ruleRemoved, err := enforcer.DeletePermission(permissions...)
	if err != nil {
		return false, v1.ErrorRemoveFilteredPolicyFailed("remove filtered policy failed: %v", err.Error())
	}
	return ruleRemoved, nil
}

// AddPermissionForUser .
func (u *rbacUseCase) AddPermissionForUser(ctx context.Context, user string, permissions []string) (bool, error) {
	enforcer, err := u.repo.GetEnforcer(ctx)
	if err != nil {
		return false, err
	}
	ruleAdded, err := enforcer.AddPermissionForUser(user, permissions...)
	if err != nil {
		return false, v1.ErrorAddPolicyFailed("add policy failed: %v", err.Error())
	}
	return ruleAdded, nil
}

// DeletePermissionForUser .
func (u *rbacUseCase) DeletePermissionForUser(ctx context.Context, user string, permissions []string) (bool, error) {
	enforcer, err := u.repo.GetEnforcer(ctx)
	if err != nil {
		return false, err
	}
	ruleRemoved, err := enforcer.DeletePermissionForUser(user, permissions...)
	if err != nil {
		return false, v1.ErrorRemovePolicyFailed("remove policy failed: %s", err.Error())
	}
	return ruleRemoved, nil
}

// DeletePermissionsForUser .
func (u *rbacUseCase) DeletePermissionsForUser(ctx context.Context, user string) (bool, error) {
	enforcer, err := u.repo.GetEnforcer(ctx)
	if err != nil {
		return false, err
	}
	ruleRemoved, err := enforcer.DeletePermissionsForUser(user)
	if err != nil {
		return false, v1.ErrorRemoveFilteredPolicyFailed("remove filtered policy failed: %v", err.Error())
	}
	return ruleRemoved, nil
}

// HasPermissionForUser .
func (u *rbacUseCase) HasPermissionForUser(ctx context.Context, user string, permissions []string) (bool, error) {
	enforcer, err := u.repo.GetEnforcer(ctx)
	if err != nil {
		return false, err
	}
	return enforcer.HasPermissionForUser(user, permissions...), nil
}
