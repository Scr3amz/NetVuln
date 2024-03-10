package netvuln

import (
	"context"
	"net"
	"regexp"


	"github.com/Scr3amz/NetVuln/internal/models"
	vulnv1 "github.com/Scr3amz/NetVuln/protos/gen"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

// validateVulnRequest checks the validity of the input data
func validateVulnRequest(req *vulnv1.CheckVulnRequest) error {
	if len(req.Targets) == 0 {
		return status.Error(codes.InvalidArgument, "target IPs is required")
	}

	if len(req.TcpPort) == 0 {
		return status.Error(codes.InvalidArgument, "tcp ports is required")
	}

	for _, target := range req.Targets {
		if target == "" {
			return status.Error(codes.InvalidArgument, "target address must not be empty")
		}
		if (isValidIP(target) || isValidDomain(target)) == false {
			return status.Error(codes.InvalidArgument, "the target must be an ip address or domain")
		}
	}

	for _, port := range req.TcpPort {
		if port > 65535 || port < 0 {
			return status.Error(codes.InvalidArgument, "invalid port value")
		}
	}

	return nil
}

// isValidIP checks the validity of the ip address.
func isValidIP(ip string) bool {
	addr := net.ParseIP(ip)
	return addr != nil
}

// isValidDomain checks the validity of the domain.
func isValidDomain(domain string) bool {
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9.-]+$`)
	return domainRegex.MatchString(domain)
}