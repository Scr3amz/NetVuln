package main

import (
	"os"
	"os/signal"
	"syscall"

	grpcapp "github.com/Scr3amz/NetVuln/internal/app/grpc"
	"github.com/Scr3amz/NetVuln/internal/config"
	"github.com/Scr3amz/NetVuln/internal/logger"
)

func main() {
	config := config.MustLoad()

	log := logger.NewLogger(config.Env)

	log.Info("starting application" )

	application := grpcapp.NewApp(log, config.GRPC.Port)

	go func() {
		application.MustRun()
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, syscall.SIGINT)

	<-stop

	application.Stop()
	log.Info("Application stopped")

}
