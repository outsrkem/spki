package main

import (
	"time"

	"spki/src/config"
	"spki/src/database/mysql"
	"spki/src/pkg/cache"
	"spki/src/route"
	"spki/src/service/cacert"
	"spki/src/slog"

	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/hlog"
)

func init() {
	config.Initializer()
}

func main() {

	cfg := config.InitConfig()
	slog.InitLogger(&cfg.Spki.Log)
	mysql.InitDB(cfg.Spki)

	cacert.InitVectorKey(cfg.Spki.Vector.K0)
	cache.InitGlobalStringCache(5 * time.Minute)

	hlog.Info("start server")
	svc := server.Default(server.WithHostPorts(cfg.Spki.App.Bind), server.WithExitWaitTime(0*time.Second))
	route.Routes(svc)
	svc.Spin()
}
