package netvuln

import (
	"context"

	vulnv1 "github.com/Scr3amz/NetVuln/protos/gen/protos/proto"
	"google.golang.org/grpc"
)

type serverAPI struct {
	vulnv1.UnimplementedNetVulnServiceServer
}

var _ vulnv1.NetVulnServiceServer = (*serverAPI)(nil)

func Register(gRPC *grpc.Server) {
	vulnv1.RegisterNetVulnServiceServer(gRPC, &serverAPI{} )
}

func (s *serverAPI) CheckVuln(ctx context.Context, r *vulnv1.CheckVulnRequest) (*vulnv1.CheckVulnResponse, error) {
	panic("implement me")
}