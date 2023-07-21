package server

import (
	v1 "github.com/devexps/go-casbin/api/gen/go/casbin_service/v1"
	"github.com/devexps/go-casbin/api/gen/go/common/conf"
	"github.com/devexps/go-casbin/casbin_service/v2/internal/service"
	"github.com/devexps/go-casbin/pkg/bootstrap"
	"github.com/devexps/go-micro/v2/log"
	"github.com/devexps/go-micro/v2/middleware/logging"
	"github.com/devexps/go-micro/v2/transport/grpc"
)

// NewGRPCServer new a gRPC server.
func NewGRPCServer(cfg *conf.Bootstrap, logger log.Logger,
	casbinSvc service.CasbinService,
) *grpc.Server {
	srv := bootstrap.CreateGrpcServer(cfg, logging.Server(logger))
	v1.RegisterCasbinServiceServer(srv, casbinSvc)
	return srv
}
