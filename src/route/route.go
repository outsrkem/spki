package route

import (
	"context"
	"net/http"
	"spki/src/service/cacert"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/utils"
)

func helloWord() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		c.JSON(http.StatusOK, utils.H{"message": "hello word"})
	}
}

func Routes(r *server.Hertz) {
	r.GET("/", helloWord())

	// CA 路由组
	ca := r.Group("/spki/ca")
	{
		ca.POST("/init", cacert.InitCa())
		ca.POST("/intermediate", cacert.IssueIntermediate())
	}

	// 末端证书路由组
	cert := r.Group("/spki/cert")
	{
		cert.POST("/endentity", cacert.IssueEndEntity())
		cert.POST("/:id/renew", cacert.RenewCert())
		cert.POST("/:id/revoke", cacert.RevokeCert())
		cert.DELETE("/:id", cacert.DeleteCert())
		cert.GET("/:id/chain", cacert.ExportCertChain())
	}

	// CRL
	r.GET("/spki/crl", cacert.DownloadCRL())
}
