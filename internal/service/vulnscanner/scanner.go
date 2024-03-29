package vulnscanner

import (
	"context"
	"fmt"
	"log/slog"
	"math"
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

// GetVuln scans target addresses and tcp port, getting
// information about vulnerabilities on each port.
func (s VulnScanner) GetVuln(ctx context.Context, targets []string, tcpPorts []int32) ([]models.TargetResult, error) {
	const op = "vulnscanner.GetVuln"

	tcpPortString := intSliceToString(tcpPorts)

	log := s.log.With(
		slog.String("op", op),
		slog.String("tcpPorts", tcpPortString),
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
				Vulns:   vulnsForPort(port),
			}
			services = append(services, service)
		}
		targetResault.Services = services
		targetResaults = append(targetResaults, targetResault)
	}

	log.Info("scanning complete ")

	return targetResaults, nil
}

// intSliceToString convert a slice of int32 to string.
func intSliceToString(arr []int32) string {
	strArr := make([]string, len(arr))

	for i, num := range arr {
		strArr[i] = strconv.Itoa(int(num))
	}

	result := strings.Join(strArr, ",")
	return result
}

// vulnsForPort returns slice of vulnerabilities found on tcp port.
// If the port has no vulnerabilities, returns an empty slice.
func vulnsForPort(port nmap.Port) []models.Vuln {
	vulns := make([]models.Vuln, 0)
	if len(port.Scripts) < 1 {
		return vulns
	}

	for _, script := range port.Scripts {
		for _, table := range script.Tables {
			for _, subTable := range table.Tables {
				var cvss, id string
				for _, el := range subTable.Elements {
					if el.Key == "id" {
						id = el.Value
					}
					if el.Key == "cvss" {
						cvss = el.Value
					}
				}
				floatCVSS := MustConverseToFloat32(cvss)
				if floatCVSS == 0 {
					break
				}
				vuln := models.Vuln{
					Identifier: id,
					CvssScore:  floatCVSS,
				}
				vulns = append(vulns, vuln)

			}
		}
	}
	return vulns
}

// MustConverseToFloat32 converts a string with cvss-code into float32.
// Returns 0 if the conversion failed
func MustConverseToFloat32(cvss string) float32 {
	res, err := strconv.ParseFloat(cvss, 32)
	if err != nil {
		return 0
	}
	res = math.Round(res*10) / 10
	return float32(res)
}
