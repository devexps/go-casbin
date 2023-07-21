package service

import (
	"context"
	v1 "github.com/devexps/go-casbin/api/gen/go/casbin_service/v1"
	"github.com/devexps/go-casbin/casbin_service/v2/internal/biz"
	"github.com/devexps/go-micro/v2/log"
	"google.golang.org/protobuf/types/known/emptypb"
)

type CasbinService interface {
	v1.CasbinServiceServer
}

// CasbinService is a casbin service.
type casbinService struct {
	v1.UnimplementedCasbinServiceServer

	log       *log.Helper
	enforceUC biz.EnforceUseCase
	policyUC  biz.PolicyUseCase
	basicUC   biz.BasicUseCase
	rbacUC    biz.RBACUseCase
}

// NewCasbinService new a casbin service.
func NewCasbinService(logger log.Logger,
	enforceUC biz.EnforceUseCase,
	policyUC biz.PolicyUseCase,
	basicUC biz.BasicUseCase,
	rbacUC biz.RBACUseCase,
) CasbinService {
	l := log.NewHelper(log.With(logger, "module", "casbin_service/service"))
	return &casbinService{
		log:       l,
		enforceUC: enforceUC,
		policyUC:  policyUC,
		basicUC:   basicUC,
		rbacUC:    rbacUC,
	}
}

// Enforce .
func (s *casbinService) Enforce(ctx context.Context, req *v1.EnforceRequest) (*v1.BoolReply, error) {
	allowed, err := s.enforceUC.Enforce(ctx, req.GetParams())
	if err != nil {
		return nil, err
	}
	return &v1.BoolReply{Res: allowed}, nil
}

// LoadPolicy .
func (s *casbinService) LoadPolicy(ctx context.Context, req *emptypb.Empty) (*emptypb.Empty, error) {
	if err := s.policyUC.LoadPolicy(ctx); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

// SavePolicy .
func (s *casbinService) SavePolicy(ctx context.Context, req *emptypb.Empty) (*emptypb.Empty, error) {
	if err := s.policyUC.SavePolicy(ctx); err != nil {
		return nil, err
	}
	return &emptypb.Empty{}, nil
}

// AddPolicy .
func (s *casbinService) AddPolicy(ctx context.Context, req *v1.PolicyRequest) (*v1.BoolReply, error) {
	req.PType = "p"
	return s.AddNamedPolicy(ctx, req)
}

// AddNamedPolicy .
func (s *casbinService) AddNamedPolicy(ctx context.Context, req *v1.PolicyRequest) (*v1.BoolReply, error) {
	ruleAdded, err := s.policyUC.AddNamedPolicy(ctx, req.GetPType(), req.GetParams())
	if err != nil {
		return nil, err
	}
	return &v1.BoolReply{Res: ruleAdded}, nil
}

// RemovePolicy .
func (s *casbinService) RemovePolicy(ctx context.Context, req *v1.PolicyRequest) (*v1.BoolReply, error) {
	req.PType = "p"
	return s.RemoveNamedPolicy(ctx, req)
}

// RemoveNamedPolicy .
func (s *casbinService) RemoveNamedPolicy(ctx context.Context, req *v1.PolicyRequest) (*v1.BoolReply, error) {
	ruleRemoved, err := s.policyUC.RemoveNamedPolicy(ctx, req.GetPType(), req.GetParams())
	if err != nil {
		return nil, err
	}
	return &v1.BoolReply{Res: ruleRemoved}, nil
}

// RemoveFilteredPolicy .
func (s *casbinService) RemoveFilteredPolicy(ctx context.Context, req *v1.FilteredPolicyRequest) (*v1.BoolReply, error) {
	req.PType = "p"
	return s.RemoveFilteredNamedPolicy(ctx, req)
}

// RemoveFilteredNamedPolicy .
func (s *casbinService) RemoveFilteredNamedPolicy(ctx context.Context, req *v1.FilteredPolicyRequest) (*v1.BoolReply, error) {
	ruleRemoved, err := s.policyUC.RemoveFilteredNamedPolicy(ctx, req.GetPType(), req.GetFieldIndex(), req.GetFieldValues())
	if err != nil {
		return nil, err
	}
	return &v1.BoolReply{Res: ruleRemoved}, nil
}

// GetPolicy .
func (s *casbinService) GetPolicy(ctx context.Context, req *emptypb.Empty) (*v1.Array2DReply, error) {
	return s.GetNamedPolicy(ctx, &v1.PolicyRequest{PType: "p"})
}

// GetNamedPolicy .
func (s *casbinService) GetNamedPolicy(ctx context.Context, req *v1.PolicyRequest) (*v1.Array2DReply, error) {
	res, err := s.policyUC.GetNamedPolicy(ctx, req.GetPType())
	if err != nil {
		return nil, err
	}
	return res, nil
}

// GetFilteredPolicy .
func (s *casbinService) GetFilteredPolicy(ctx context.Context, req *v1.FilteredPolicyRequest) (*v1.Array2DReply, error) {
	req.PType = "p"
	return s.GetFilteredNamedPolicy(ctx, req)
}

// GetFilteredNamedPolicy .
func (s *casbinService) GetFilteredNamedPolicy(ctx context.Context, req *v1.FilteredPolicyRequest) (*v1.Array2DReply, error) {
	res, err := s.policyUC.GetFilteredNamedPolicy(ctx, req.GetPType(), req.GetFieldIndex(), req.GetFieldValues())
	if err != nil {
		return nil, err
	}
	return res, nil
}

// AddGroupingPolicy .
func (s *casbinService) AddGroupingPolicy(ctx context.Context, req *v1.PolicyRequest) (*v1.BoolReply, error) {
	req.PType = "g"
	return s.AddNamedGroupingPolicy(ctx, req)
}

// AddNamedGroupingPolicy .
func (s *casbinService) AddNamedGroupingPolicy(ctx context.Context, req *v1.PolicyRequest) (*v1.BoolReply, error) {
	ruleAdded, err := s.policyUC.AddNamedGroupingPolicy(ctx, req.GetPType(), req.GetParams())
	if err != nil {
		return nil, err
	}
	return &v1.BoolReply{Res: ruleAdded}, nil
}

// RemoveGroupingPolicy .
func (s *casbinService) RemoveGroupingPolicy(ctx context.Context, req *v1.PolicyRequest) (*v1.BoolReply, error) {
	req.PType = "g"
	return s.RemoveNamedGroupingPolicy(ctx, req)
}

// RemoveNamedGroupingPolicy .
func (s *casbinService) RemoveNamedGroupingPolicy(ctx context.Context, req *v1.PolicyRequest) (*v1.BoolReply, error) {
	ruleRemoved, err := s.policyUC.RemoveNamedGroupingPolicy(ctx, req.GetPType(), req.GetParams())
	if err != nil {
		return nil, err
	}
	return &v1.BoolReply{Res: ruleRemoved}, nil
}

// RemoveFilteredGroupingPolicy .
func (s *casbinService) RemoveFilteredGroupingPolicy(ctx context.Context, req *v1.FilteredPolicyRequest) (*v1.BoolReply, error) {
	req.PType = "g"
	return s.RemoveFilteredNamedGroupingPolicy(ctx, req)
}

// RemoveFilteredNamedGroupingPolicy .
func (s *casbinService) RemoveFilteredNamedGroupingPolicy(ctx context.Context, req *v1.FilteredPolicyRequest) (*v1.BoolReply, error) {
	ruleRemoved, err := s.policyUC.RemoveFilteredNamedGroupingPolicy(ctx, req.GetPType(), req.GetFieldIndex(), req.GetFieldValues())
	if err != nil {
		return nil, err
	}
	return &v1.BoolReply{Res: ruleRemoved}, nil
}

// GetGroupingPolicy .
func (s *casbinService) GetGroupingPolicy(ctx context.Context, req *emptypb.Empty) (*v1.Array2DReply, error) {
	return s.GetNamedGroupingPolicy(ctx, &v1.PolicyRequest{PType: "g"})
}

// GetNamedGroupingPolicy .
func (s *casbinService) GetNamedGroupingPolicy(ctx context.Context, req *v1.PolicyRequest) (*v1.Array2DReply, error) {
	res, err := s.policyUC.GetNamedGroupingPolicy(ctx, req.GetPType())
	if err != nil {
		return nil, err
	}
	return res, nil
}

// GetFilteredGroupingPolicy .
func (s *casbinService) GetFilteredGroupingPolicy(ctx context.Context, req *v1.FilteredPolicyRequest) (*v1.Array2DReply, error) {
	req.PType = "g"
	return s.GetFilteredNamedGroupingPolicy(ctx, req)
}

// GetFilteredNamedGroupingPolicy .
func (s *casbinService) GetFilteredNamedGroupingPolicy(ctx context.Context, req *v1.FilteredPolicyRequest) (*v1.Array2DReply, error) {
	res, err := s.policyUC.GetFilteredNamedGroupingPolicy(ctx, req.GetPType(), req.GetFieldIndex(), req.GetFieldValues())
	if err != nil {
		return nil, err
	}
	return res, nil
}

// GetAllSubjects .
func (s *casbinService) GetAllSubjects(ctx context.Context, req *emptypb.Empty) (*v1.ArrayReply, error) {
	return s.GetAllNamedSubjects(ctx, &v1.SimpleGetRequest{PType: "p"})
}

// GetAllNamedSubjects .
func (s *casbinService) GetAllNamedSubjects(ctx context.Context, req *v1.SimpleGetRequest) (*v1.ArrayReply, error) {
	res, err := s.basicUC.GetAllNamedSubjects(ctx, req.GetPType())
	if err != nil {
		return nil, err
	}
	return res, nil
}

// GetAllObjects .
func (s *casbinService) GetAllObjects(ctx context.Context, req *emptypb.Empty) (*v1.ArrayReply, error) {
	return s.GetAllNamedObjects(ctx, &v1.SimpleGetRequest{PType: "p"})
}

// GetAllNamedObjects .
func (s *casbinService) GetAllNamedObjects(ctx context.Context, req *v1.SimpleGetRequest) (*v1.ArrayReply, error) {
	res, err := s.basicUC.GetAllNamedObjects(ctx, req.GetPType())
	if err != nil {
		return nil, err
	}
	return res, nil
}

// GetAllActions .
func (s *casbinService) GetAllActions(ctx context.Context, req *emptypb.Empty) (*v1.ArrayReply, error) {
	return s.GetAllNamedActions(ctx, &v1.SimpleGetRequest{PType: "p"})
}

// GetAllNamedActions .
func (s *casbinService) GetAllNamedActions(ctx context.Context, req *v1.SimpleGetRequest) (*v1.ArrayReply, error) {
	res, err := s.basicUC.GetAllNamedActions(ctx, req.GetPType())
	if err != nil {
		return nil, err
	}
	return res, nil
}

// GetAllRoles .
func (s *casbinService) GetAllRoles(ctx context.Context, req *emptypb.Empty) (*v1.ArrayReply, error) {
	return s.GetAllNamedRoles(ctx, &v1.SimpleGetRequest{PType: "g"})
}

// GetAllNamedRoles .
func (s *casbinService) GetAllNamedRoles(ctx context.Context, req *v1.SimpleGetRequest) (*v1.ArrayReply, error) {
	res, err := s.basicUC.GetAllNamedRoles(ctx, req.GetPType())
	if err != nil {
		return nil, err
	}
	return res, nil
}

// HasPolicy .
func (s *casbinService) HasPolicy(ctx context.Context, req *v1.PolicyRequest) (*v1.BoolReply, error) {
	req.PType = "p"
	return s.HasNamedPolicy(ctx, req)
}

// HasNamedPolicy .
func (s *casbinService) HasNamedPolicy(ctx context.Context, req *v1.PolicyRequest) (*v1.BoolReply, error) {
	b, err := s.basicUC.HasNamedPolicy(ctx, req.GetPType(), req.GetParams())
	if err != nil {
		return nil, err
	}
	return &v1.BoolReply{Res: b}, nil
}

// HasGroupingPolicy .
func (s *casbinService) HasGroupingPolicy(ctx context.Context, req *v1.PolicyRequest) (*v1.BoolReply, error) {
	req.PType = "g"
	return s.HasNamedGroupingPolicy(ctx, req)
}

// HasNamedGroupingPolicy .
func (s *casbinService) HasNamedGroupingPolicy(ctx context.Context, req *v1.PolicyRequest) (*v1.BoolReply, error) {
	b, err := s.basicUC.HasNamedGroupingPolicy(ctx, req.GetPType(), req.GetParams())
	if err != nil {
		return nil, err
	}
	return &v1.BoolReply{Res: b}, nil
}

// GetRolesForUser .
func (s *casbinService) GetRolesForUser(ctx context.Context, req *v1.UserRoleRequest) (*v1.ArrayReply, error) {
	res, err := s.rbacUC.GetRolesForUser(ctx, req.GetUser())
	if err != nil {
		return nil, err
	}
	return &v1.ArrayReply{Array: res}, nil
}

// GetImplicitRolesForUser .
func (s *casbinService) GetImplicitRolesForUser(ctx context.Context, req *v1.UserRoleRequest) (*v1.ArrayReply, error) {
	res, err := s.rbacUC.GetImplicitRolesForUser(ctx, req.GetUser())
	if err != nil {
		return nil, err
	}
	return &v1.ArrayReply{Array: res}, nil
}

// GetUsersForRole .
func (s *casbinService) GetUsersForRole(ctx context.Context, req *v1.UserRoleRequest) (*v1.ArrayReply, error) {
	res, err := s.rbacUC.GetUsersForRole(ctx, req.GetRole())
	if err != nil {
		return nil, err
	}
	return &v1.ArrayReply{Array: res}, nil
}

// HasRoleForUser .
func (s *casbinService) HasRoleForUser(ctx context.Context, req *v1.UserRoleRequest) (*v1.BoolReply, error) {
	b, err := s.rbacUC.HasRoleForUser(ctx, req.GetUser(), req.GetRole())
	if err != nil {
		return nil, err
	}
	return &v1.BoolReply{Res: b}, nil
}

// AddRoleForUser .
func (s *casbinService) AddRoleForUser(ctx context.Context, req *v1.UserRoleRequest) (*v1.BoolReply, error) {
	b, err := s.rbacUC.AddRoleForUser(ctx, req.GetUser(), req.GetRole())
	if err != nil {
		return nil, err
	}
	return &v1.BoolReply{Res: b}, nil
}

// DeleteRoleForUser .
func (s *casbinService) DeleteRoleForUser(ctx context.Context, req *v1.UserRoleRequest) (*v1.BoolReply, error) {
	b, err := s.rbacUC.DeleteRoleForUser(ctx, req.GetUser(), req.GetRole())
	if err != nil {
		return nil, err
	}
	return &v1.BoolReply{Res: b}, nil
}

// DeleteRolesForUser .
func (s *casbinService) DeleteRolesForUser(ctx context.Context, req *v1.UserRoleRequest) (*v1.BoolReply, error) {
	b, err := s.rbacUC.DeleteRolesForUser(ctx, req.GetUser())
	if err != nil {
		return nil, err
	}
	return &v1.BoolReply{Res: b}, nil
}

// DeleteUser .
func (s *casbinService) DeleteUser(ctx context.Context, req *v1.UserRoleRequest) (*v1.BoolReply, error) {
	b, err := s.rbacUC.DeleteUser(ctx, req.GetUser())
	if err != nil {
		return nil, err
	}
	return &v1.BoolReply{Res: b}, nil
}

// DeleteRole .
func (s *casbinService) DeleteRole(ctx context.Context, req *v1.UserRoleRequest) (*v1.BoolReply, error) {
	b, err := s.rbacUC.DeleteRole(ctx, req.GetRole())
	if err != nil {
		return nil, err
	}
	return &v1.BoolReply{Res: b}, nil
}

// GetPermissionsForUser .
func (s *casbinService) GetPermissionsForUser(ctx context.Context, req *v1.PermissionRequest) (*v1.Array2DReply, error) {
	res, err := s.rbacUC.GetPermissionsForUser(ctx, req.GetUser())
	if err != nil {
		return nil, err
	}
	return res, nil
}

// GetImplicitPermissionsForUser .
func (s *casbinService) GetImplicitPermissionsForUser(ctx context.Context, req *v1.PermissionRequest) (*v1.Array2DReply, error) {
	res, err := s.rbacUC.GetImplicitPermissionsForUser(ctx, req.GetUser())
	if err != nil {
		return nil, err
	}
	return res, nil
}

// DeletePermission .
func (s *casbinService) DeletePermission(ctx context.Context, req *v1.PermissionRequest) (*v1.BoolReply, error) {
	b, err := s.rbacUC.DeletePermission(ctx, req.GetPermissions())
	if err != nil {
		return nil, err
	}
	return &v1.BoolReply{Res: b}, nil
}

// AddPermissionForUser .
func (s *casbinService) AddPermissionForUser(ctx context.Context, req *v1.PermissionRequest) (*v1.BoolReply, error) {
	b, err := s.rbacUC.AddPermissionForUser(ctx, req.GetUser(), req.GetPermissions())
	if err != nil {
		return nil, err
	}
	return &v1.BoolReply{Res: b}, nil
}

// DeletePermissionForUser .
func (s *casbinService) DeletePermissionForUser(ctx context.Context, req *v1.PermissionRequest) (*v1.BoolReply, error) {
	b, err := s.rbacUC.DeletePermissionForUser(ctx, req.GetUser(), req.GetPermissions())
	if err != nil {
		return nil, err
	}
	return &v1.BoolReply{Res: b}, nil
}

// DeletePermissionsForUser .
func (s *casbinService) DeletePermissionsForUser(ctx context.Context, req *v1.PermissionRequest) (*v1.BoolReply, error) {
	b, err := s.rbacUC.DeletePermissionsForUser(ctx, req.GetUser())
	if err != nil {
		return nil, err
	}
	return &v1.BoolReply{Res: b}, nil
}

// HasPermissionForUser .
func (s *casbinService) HasPermissionForUser(ctx context.Context, req *v1.PermissionRequest) (*v1.BoolReply, error) {
	b, err := s.rbacUC.HasPermissionForUser(ctx, req.GetUser(), req.GetPermissions())
	if err != nil {
		return nil, err
	}
	return &v1.BoolReply{Res: b}, nil
}
