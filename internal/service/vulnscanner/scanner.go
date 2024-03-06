package vulnscanner

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/Scr3amz/NetVuln/internal/models"
	"github.com/Ullaakut/nmap/v3"
)

type VulnScanner struct {
	log *slog.Logger
}

func NewVulnScanner(log *slog.Logger) *VulnScanner {
	return &VulnScanner{
		log: log,
	}
}

func (s VulnScanner) GetVuln(ctx context.Context, targets []string, tcpPorts []int32) ([]models.TargetResult, error) {
	const op = "vulnscanner.GetVuln"

	tcpPortString := intSliceToString(tcpPorts)

	log := s.log.With(
		slog.String("op", op),
		slog.String("tcpPorts", tcpPortString ),
		slog.String("IPs", strings.Join(targets, ", ")),
	)

	log.Info("attempt to find vulnerabilities")

	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(targets...),
		nmap.WithScripts("vulners.nse"),
		nmap.WithPorts(tcpPortString),
		nmap.WithServiceInfo(),
	)

	if err != nil {
		s.log.Error("nmap not found", slog.Attr{
			Key:   "error",
			Value: slog.StringValue(err.Error()),
		})

		return nil, fmt.Errorf("%s: %w", op, err)
	}

	result, warnings, err := scanner.Run()

	if len(*warnings) > 0 {
		s.log.Warn("occurred problems with reading stdout", slog.Attr{
			Key:   "warning",
			Value: slog.StringValue(strings.Join(*warnings, "\n")),
		})
	}

	if err != nil {
		s.log.Error("unable to run nmap scan", slog.Attr{
			Key:   "error",
			Value: slog.StringValue(err.Error()),
		})

		return nil, fmt.Errorf("%s: %w", op, err)
	}

	targetResaults := make([]models.TargetResult, 0)

	for _, host := range result.Hosts {
		targetResault := models.TargetResult{
			Target: host.Addresses[0].Addr,
		}
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			log.Info("unable to find any ports or addresses")
			break
		}

		services := make([]models.Service, 0)

		for _, port := range host.Ports {
			service := models.Service{
				Name:    port.Service.Name,
				Version: port.Service.Product + " " + port.Service.Version,
				TcpPort: int32(port.ID),
				//TODO: добавить уязвимости
			}
			services = append(services, service)
		}
		targetResault.Services = services
		targetResaults = append(targetResaults, targetResault)
	}

	log.Info("scanning complete ")

	return targetResaults, nil
}

func intSliceToString(arr []int32) string {
	strArr := make([]string, len(arr))

	for i, num := range arr {
		strArr[i] = strconv.Itoa(int(num))
	}

	result := strings.Join(strArr, ",")
	return result
}
