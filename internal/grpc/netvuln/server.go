package netvuln

import (
	"context"
	"time"

	"github.com/Scr3amz/NetVuln/internal/models"
	vulnv1 "github.com/Scr3amz/NetVuln/protos/gen"
	"google.golang.org/grpc"
)

type serverAPI struct {
	vulnv1.UnimplementedNetVulnServiceServer
	scanner models.VulnScanner
}

var _ vulnv1.NetVulnServiceServer = (*serverAPI)(nil)

func Register(gRPC *grpc.Server, scanner models.VulnScanner) {
	vulnv1.RegisterNetVulnServiceServer(gRPC, &serverAPI{scanner: scanner})
}

func (s *serverAPI) CheckVuln(ctx context.Context, r *vulnv1.CheckVulnRequest) (*vulnv1.CheckVulnResponse, error) {
	err := validateVulnRequest(r)
	if err != nil {
		return nil, err
	}

	// TODO: протестировать получение ответа (логика приложения)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	nmapData, err := s.scanner.GetVuln(ctx, r.Targets, r.TcpPort)

	var response vulnv1.CheckVulnResponse

	for _, targetResult := range nmapData {
		var grpcTarget vulnv1.TargetResult
		grpcTarget.Target = targetResult.Target
		for _, service := range targetResult.Services {
			grpcService := vulnv1.Service{
				Name: service.Name,
				Version: service.Version,
				TcpPort: service.TcpPort,
			}
			for _, vuln := range service.Vulns {
				vuln := vulnv1.Vulnerability{
					Identifier: vuln.Identifier,
					CvssScore: vuln.CvssScore,
				}
				grpcService.Vulns = append(grpcService.Vulns, &vuln)
			}
			grpcTarget.Services = append(grpcTarget.Services, &grpcService)
		}
		response.Results = append(response.Results, &grpcTarget)

	}

	return &response, nil
}

func validateVulnRequest(req *vulnv1.CheckVulnRequest) error {
	// TODO: написать логику валидации входных данных
	return nil
}
