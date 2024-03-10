package suite

import (
	"context"
	"net"
	"os"
	"strconv"
	"testing"

	"github.com/Scr3amz/NetVuln/internal/config"
	vulnv1 "github.com/Scr3amz/NetVuln/protos/gen"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Suite struct {
	*testing.T                             // Потребуется для вызова методов *testing.T внутри Suite
	Config     *config.Config              // Конфигурация приложения
	VulnClient vulnv1.NetVulnServiceClient // Клиент для взаимодействия с gRPC-сервером
}

const (
	grpcHost = "localhost"
	keyEnv = "CONFIG_PATH"
)

// NewSuite creates new test suite.
func NewSuite(t *testing.T) (context.Context, *Suite) {
	t.Helper()
	t.Parallel()

	config := config.MustLoadPath(configPath())

	ctx, cancelCtx := context.WithTimeout(context.Background(), config.GRPC.Timeout)

	t.Cleanup(func() {
		t.Helper()
		cancelCtx()
	})

	cc, err := grpc.DialContext(
		context.Background(),
		grpcAddress(config),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)

	if err != nil {
		t.Fatalf("grpc server connection failed: %v", err)
	}

	return ctx, &Suite{
		T:          t,
		Config:     config,
		VulnClient: vulnv1.NewNetVulnServiceClient(cc),
	}
}

func configPath() string {

	if v := os.Getenv(keyEnv); v != "" {
		return v
	}

	return "../config/local_tests.yaml"
}

func grpcAddress(config *config.Config) string {
	return net.JoinHostPort(grpcHost, strconv.Itoa(config.GRPC.Port))
}
