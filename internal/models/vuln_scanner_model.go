package models

import "context"

type VulnScanner interface {
	GetVuln(
		ctx context.Context,
		targets []string,
		tcpPorts []int32,
	) (resault []TargetResult, err error)
}

type TargetResult struct {
	Target   string
	Services []Service
}

type Service struct {
	Name    string
	Version string
	TcpPort int32
	Vulns   []Vuln
}

type Vuln struct {
	Identifier string
	CvssScore  float32
}
