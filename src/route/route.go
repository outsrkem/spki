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
	r.HEAD("")             // 健康检查
	r.GET("", helloWord()) // 健康检查

	// CA
	r.POST("/spki/ca/init", cacert.InitCa())                    // 初始化根 CA
	r.POST("/spki/ca/intermediate", cacert.IssueIntermediate()) // 签发中间 CA

	r.POST("/spki/cert/endentity", cacert.IssueEndEntity()) // 签发末端证书
	r.GET("/spki/cert/list", cacert.ListCert())             // 列出证书，支持 ?genre=1&genre=2

	// 单证书操作
	r.POST("/spki/cert/:id/renew", cacert.RenewCert())          // 续签，只延长有效期
	r.POST("/spki/cert/:id/revoke", cacert.RevokeCert())        // 吊销
	r.DELETE("/spki/cert/:id", cacert.DeleteCert())             // 删除，同时删私钥和所有版本
	r.GET("/spki/cert/:id/chain", cacert.ExportCertChain())     // 导出链，支持 ?includeRoot=false&onlyRoot=true
	r.GET("/spki/cert/:id/root", cacert.FindRootCA())           // 从任意证书向上找根 CA
	r.GET("/spki/cert/:id/versions", cacert.ListCertVersions()) // 列出某证书所有版本
	r.GET("/spki/crl", cacert.DownloadCRL())                    // 下载 CRL，参数 ?issuerId=xxx
}
