package grpcapp

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/Scr3amz/NetVuln/internal/grpc/netvuln"
	"github.com/Scr3amz/NetVuln/internal/service/vulnscanner"
	"google.golang.org/grpc"
)

type App struct {
	log        *slog.Logger
	gRPCServer *grpc.Server
	port       int
}

func NewApp(log *slog.Logger, port int) *App {
	gRPCServer := grpc.NewServer()

	// TODO: fix to normal scanner
	scanner := vulnscanner.NewVulnScanner(log)
	netvuln.Register(gRPCServer, scanner)

	return &App{
		log:        log,
		gRPCServer: gRPCServer,
		port:       port,
	}
}

func (a *App) MustRun() {
	if err := a.Run(); err != nil {
		panic(err)
	}
}

func (a *App) Run() error {
	const op = "grpcapp.Run"

	log := a.log.With(
		slog.String("op", op),
		slog.Int("port", a.port),
	)

	listner, err := net.Listen("tcp", fmt.Sprintf(":%d", a.port))
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("gRPC server running", slog.String("addr", listner.Addr().String()))

	if err := a.gRPCServer.Serve(listner); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

func (a *App) Stop() {
	const op = "grpcapp.Stop"

	a.log.With(slog.String("op", op)).Info("stopping grpc server", slog.Int("port", a.port))

	a.gRPCServer.GracefulStop()
}
