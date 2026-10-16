package route

import (
	"context"
	"net/http"
	"spki/src/pkg/answer"
	"spki/src/service/cacert"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/utils"
)

func Middleware(h *server.Hertz) {
	h.Use(RequestId())
	h.Use(RequestRecorder())
}

func helloWorld() func(c context.Context, ctx *app.RequestContext) {
	return func(c context.Context, ctx *app.RequestContext) {
		ctx.JSON(http.StatusOK, utils.H{"message": "Hello World"})
	}
}
func r404() func(ctx context.Context, c *app.RequestContext) {
	return func(ctx context.Context, c *app.RequestContext) {
		c.JSON(http.StatusNotFound, answer.ResBody(answer.Ecode404, "The API does not exist.", nil))
	}
}

func AppRoute(h *server.Hertz) {
	h.HEAD("")              // 健康检查
	h.GET("", helloWorld()) // 健康检查

	// CA
	h.POST("/v1/spki/ca/init", apc("turtle:people:list"), cacert.InitCa())                    // 初始化根 CA
	h.POST("/v1/spki/ca/intermediate", apc("turtle:people:list"), cacert.IssueIntermediate()) // 签发中间 CA
	h.POST("/v1/spki/ca/import", apc("turtle:people:list"), cacert.ImportCA())                // 导入CA

	// 证书操作
	h.POST("/v1/spki/cert/endentity", apc("turtle:people:list"), cacert.IssueEndEntity())     // 签发末端证书
	h.GET("/v1/spki/cert/list", apc("turtle:people:list"), cacert.ListCert())                 // 列出证书，支持 ?genre=1&genre=2
	h.POST("/v1/spki/cert/:id/renew", apc("turtle:people:list"), cacert.RenewCert())          // 续签，只延长有效期
	h.POST("/v1/spki/cert/:id/revoke", apc("turtle:people:list"), cacert.RevokeCert())        // 吊销
	h.DELETE("/v1/spki/cert/:id", apc("turtle:people:list"), cacert.DeleteCert())             // 删除，同时删私钥和所有版本
	h.GET("/v1/spki/cert/:id/chain", apc("turtle:people:list"), cacert.ExportCertChain())     // 导出链，支持 ?includeRoot=false&onlyRoot=true
	h.GET("/v1/spki/cert/:id/root", apc("turtle:people:list"), cacert.FindRootCA())           // 从任意证书向上找根 CA
	h.GET("/v1/spki/cert/:id/versions", apc("turtle:people:list"), cacert.ListCertVersions()) // 列出某证书所有版本
	h.GET("/v1/spki/cert/:id/bundle", apc("turtle:people:list"), cacert.ExportCertBundle())   // 下载证书含私钥
	h.GET("/v1/spki/crl", apc("turtle:people:list"), cacert.DownloadCRL())                    // 下载 CRL，参数 ?issuerId=xxx

	h.NoRoute(r404())
}
