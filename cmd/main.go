package main

import (
	grpcapp "github.com/Scr3amz/NetVuln/internal/app/grpc"
	"github.com/Scr3amz/NetVuln/internal/logger"
)

func main() {
	log := logger.NewLogger("local")

	log.Info("starting application" )

	//TODO: add config

	//TODO: add start of app
	application := grpcapp.NewApp(log, 123)

	application.MustRun()

}
