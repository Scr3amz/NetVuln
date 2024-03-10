package tests

import (
	"math/rand"
	"testing"

	vulnv1 "github.com/Scr3amz/NetVuln/protos/gen"
	"github.com/Scr3amz/NetVuln/tests/suite"
	"github.com/brianvoe/gofakeit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	maxPort = 65535
	numberOfAddresses = 5
	numberOfPorts = 5
)

func TestCheckVuln_HappyPath(t *testing.T) {
	ctx, st := suite.NewSuite(t)

	targetAdresses := randomFakeIPAddress(numberOfAddresses)
	tcpPorts := randomPorts(numberOfPorts)

	res, err := st.VulnClient.CheckVuln(ctx, &vulnv1.CheckVulnRequest{
		Targets: targetAdresses,
		TcpPort: tcpPorts,
	})

	require.NoError(t, err)
	assert.NotEmpty(t, res.GetResults())
}

func TestCheckVuln_FailCases(t *testing.T) {
	ctx, st := suite.NewSuite(t)
	tests := []struct {
		name        string
		targets     []string
		tcpPorts    []int32
		expectedErr string
	}{
		{
			name:        "CheckVuln with empty targets slice",
			targets:     []string{},
			tcpPorts:    randomPorts(numberOfPorts),
			expectedErr: "target IPs is required",
		},
		{
			name:        "CheckVuln with empty ports slice",
			targets:     randomFakeIPAddress(numberOfAddresses),
			tcpPorts:    []int32{},
			expectedErr: "tcp ports is required",
		},
		{
			name:        "CheckVuln with empty 1 or more empty target",
			targets:     []string{"google.com", "youtube.com", ""},
			tcpPorts:    randomPorts(numberOfPorts),
			expectedErr: "target address must not be empty",
		},
		{
			name:        "CheckVuln with port out of bounds",
			targets:     randomFakeIPAddress(numberOfAddresses),
			tcpPorts:    []int32{22, 80, -9},
			expectedErr: "invalid port value",
		},
		{
			name:        "CheckVuln with invalid targets",
			targets:     []string{"google.com", "youtube.com", "worivowrivjodfvw'dcwewec,,wef.wef.d"},
			tcpPorts:    randomPorts(numberOfPorts),
			expectedErr: "the target must be an ip address or domain",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := st.VulnClient.CheckVuln(ctx, &vulnv1.CheckVulnRequest{
				Targets: tt.targets,
				TcpPort: tt.tcpPorts,
			})
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectedErr)
		})
	}
}

func randomFakeIPAddress(count int) []string {
	res := make([]string, 0, count)
	for i := 0; i < count; i++ {
		res = append(res, gofakeit.IPv4Address())
	}
	return res
}

func randomPorts(count int) []int32 {
	res := make([]int32, 0, count)
	for i := 0; i < count; i++ {
		res = append(res, rand.Int31n(maxPort+1))
	}
	return res
}
