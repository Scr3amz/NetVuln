package grpcapp

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"github.com/Scr3amz/NetVuln/internal/grpc/netvuln"
	"github.com/Scr3amz/NetVuln/internal/service/vulnscanner"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/recovery"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// App is a wrapper structure for application
type App struct {
	log        *slog.Logger
	gRPCServer *grpc.Server
	port       int
}

const (
	grpcHost = "127.0.0.1"
)

// NewApp creates new gRPC server app.
func NewApp(log *slog.Logger, port int) *App {
	loggingOpts := []logging.Option{
		logging.WithLogOnEvents(
			logging.StartCall, logging.FinishCall,
		),
	}

	recoveryOpts := []recovery.Option{
		recovery.WithRecoveryHandler(func(p interface{}) (err error) {
			log.Error("Recovered from panic", slog.Any("panic", p))
			return status.Errorf(codes.Internal, "internal error")
		}),
	}

	gRPCServer := grpc.NewServer(grpc.ChainUnaryInterceptor(
		logging.UnaryServerInterceptor(InterceptorLogger(log), loggingOpts...),
		recovery.UnaryServerInterceptor(recoveryOpts...),
	))

	scanner := vulnscanner.NewVulnScanner(log)
	netvuln.Register(gRPCServer, scanner)

	return &App{
		log:        log,
		gRPCServer: gRPCServer,
		port:       port,
	}
}

// InterceptorLogger adapts slog logger to interceptor logger.
// This code is simple enough to be copied and not imported.
func InterceptorLogger(l *slog.Logger) logging.Logger {
	return logging.LoggerFunc(func(ctx context.Context, lvl logging.Level, msg string, fields ...any) {
		l.Log(ctx, slog.Level(lvl), msg, fields...)
	})
}

// MustRun runs gRPC server and panics if any error occurs.
func (a *App) MustRun() {
	if err := a.Run(); err != nil {
		panic(err)
	}
}

// Run runs gRPC server.
func (a *App) Run() error {
	const op = "grpcapp.Run"

	log := a.log.With(
		slog.String("op", op),
		slog.Int("port", a.port),
	)

	listner, err := net.Listen("tcp", fmt.Sprintf("%s:%d", grpcHost, a.port))
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	log.Info("gRPC server running", slog.String("addr", listner.Addr().String()))

	if err := a.gRPCServer.Serve(listner); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}

	return nil
}

// Stop stops gRPC server.
func (a *App) Stop() {
	const op = "grpcapp.Stop"

	a.log.With(slog.String("op", op)).Info("stopping grpc server", slog.Int("port", a.port))

	a.gRPCServer.GracefulStop()
}

