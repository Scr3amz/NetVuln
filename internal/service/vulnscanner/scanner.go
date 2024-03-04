package vulnscanner

import (
	"context"
	"log"
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

	scanner, err := nmap.NewScanner(
		ctx,
		nmap.WithTargets(targets...),
		nmap.WithScripts("vulners.nse"),
		nmap.WithPorts(intSliceToString(tcpPorts)),
		nmap.WithServiceInfo(),
	)
	if err != nil {
		//TODO: добавить обработку ошибки
		log.Fatalf("unable to create nmap scanner: %v", err)
	}

	result, warnings, err := scanner.Run()
	if len(*warnings) > 0 {
		//TODO: добавить обработку ошибки
		log.Printf("run finished with warnings: %s\n", *warnings)
	}
	if err != nil {
		//TODO: добавить обработку ошибки
		log.Fatalf("unable to run nmap scan: %v", err)
	}

	targetResaults := make([]models.TargetResult, 0)

	// Use the results to print an example output
	for _, host := range result.Hosts {
		targetResault := models.TargetResult{
			Target: host.Addresses[0].Addr,
		}
		if len(host.Ports) == 0 || len(host.Addresses) == 0 {
			continue
		}

		services := make([]models.Service,0) 

		for _, port := range host.Ports {
			service := models.Service{
				Name: port.Service.Name,
				Version:  port.Service.Product + " " + port.Service.Version,
				TcpPort: int32(port.ID),
			}
			services = append(services, service)
		}
		targetResault.Services = services
		targetResaults = append(targetResaults, targetResault)
	}

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
