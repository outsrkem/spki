package cacert

import (
	"context"
	"net/http"

	"spki/src/pkg/answer"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/hlog"
)

// ---------- 初始化根 CA ----------

// InitCa POST /spki/ca/init
func InitCa() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var cfg CertConfig
		if err := c.BindJSON(&cfg); err != nil {
			hlog.Error("InitCa bind: ", err)
			c.JSON(http.StatusBadRequest, answer.ResBody("444", "请求体错误: "+err.Error(), ""))
			return
		}
		userID := c.GetString("userId")
		account := c.GetString("account")

		certID, err := InitRootCA(userID, account, &cfg)
		if err != nil {
			hlog.Error("InitCa: ", err)
			c.JSON(http.StatusInternalServerError, answer.ResBody("500", err.Error(), ""))
			return
		}
		c.JSON(http.StatusCreated, answer.ResBody("200", "", map[string]any{"certId": certID}))
	}
}

// ---------- 签发中间 CA ----------

// IssueIntermediate POST /spki/ca/intermediate
func IssueIntermediate() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req struct {
			CertConfig
			ParentID string `json:"parentId"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, answer.ResBody("444", err.Error(), ""))
			return
		}
		if req.ParentID == "" {
			c.JSON(http.StatusBadRequest, answer.ResBody("444", "parentId is required", ""))
			return
		}
		userID := c.GetString("userId")
		account := c.GetString("account")

		certID, err := IssueIntermediateSvc(userID, account, req.ParentID, &req.CertConfig)
		if err != nil {
			hlog.Error("IssueIntermediate: ", err)
			c.JSON(http.StatusInternalServerError, answer.ResBody("500", err.Error(), ""))
			return
		}
		c.JSON(http.StatusCreated, answer.ResBody("200", "", map[string]any{"certId": certID}))
	}
}

// ---------- 签发末端证书 ----------

// IssueEndEntity POST /spki/cert/endentity
func IssueEndEntity() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req struct {
			CertConfig
			IssuerID string `json:"issuerId"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, answer.ResBody("444", err.Error(), ""))
			return
		}
		if req.IssuerID == "" {
			c.JSON(http.StatusBadRequest, answer.ResBody("444", "issuerId is required", ""))
			return
		}
		userID := c.GetString("userId")
		account := c.GetString("account")

		certID, err := IssueEndEntitySvc(userID, account, req.IssuerID, &req.CertConfig)
		if err != nil {
			hlog.Error("IssueEndEntity: ", err)
			c.JSON(http.StatusInternalServerError, answer.ResBody("500", err.Error(), ""))
			return
		}
		c.JSON(http.StatusCreated, answer.ResBody("200", "", map[string]any{"certId": certID}))
	}
}

// ---------- 吊销 ----------

// RevokeCert POST /spki/cert/:id/revoke
func RevokeCert() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		certID := c.Param("id")
		if err := RevokeCertSvc(certID); err != nil {
			hlog.Error("RevokeCert: ", err)
			c.JSON(http.StatusInternalServerError, answer.ResBody("500", err.Error(), ""))
			return
		}
		c.JSON(http.StatusOK, answer.ResBody("200", "", map[string]any{"certId": certID, "status": "R"}))
	}
}

// ---------- 删除 ----------

// DeleteCert DELETE /spki/cert/:id
func DeleteCert() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		certID := c.Param("id")
		if err := DeleteCertSvc(certID); err != nil {
			hlog.Error("DeleteCert: ", err)
			c.JSON(http.StatusInternalServerError, answer.ResBody("500", err.Error(), ""))
			return
		}
		c.JSON(http.StatusOK, answer.ResBody("200", "", map[string]any{"certId": certID, "deleted": true}))
	}
}

// ---------- 导出链 ----------

// ExportCertChain GET /spki/cert/:id/chain
func ExportCertChain() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		certID := c.Param("id")
		includeRoot := c.DefaultQuery("includeRoot", "true") != "false"
		chain, err := BuildCertChain(certID, includeRoot)
		if err != nil {
			c.JSON(http.StatusInternalServerError, answer.ResBody("500", err.Error(), ""))
			return
		}
		c.Data(http.StatusOK, "application/x-pem-file", []byte(chain))
	}
}

// ---------- CRL ----------

// DownloadCRL GET /spki/crl?issuerId=xxx
func DownloadCRL() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		issuerID := c.Query("issuerId")
		if issuerID == "" {
			c.JSON(http.StatusBadRequest, answer.ResBody("444", "issuerId is required", ""))
			return
		}
		crl, err := BuildCRL(issuerID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, answer.ResBody("500", err.Error(), ""))
			return
		}
		c.Data(http.StatusOK, "application/x-pem-file", []byte(crl))
	}
}

// ---------- 续签 ----------

// RenewCert POST /spki/cert/:id/renew
func RenewCert() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		certID := c.Param("id")
		var req struct {
			Expiry int `json:"expiry"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, answer.ResBody("444", "请求体错误: "+err.Error(), ""))
			return
		}
		if req.Expiry <= 0 {
			c.JSON(http.StatusBadRequest, answer.ResBody("444", "expiry must be > 0", ""))
			return
		}
		rev, err := RenewCertSvc(certID, req.Expiry)
		if err != nil {
			hlog.Error("RenewCert: ", err)
			c.JSON(http.StatusInternalServerError, answer.ResBody("500", err.Error(), ""))
			return
		}
		c.JSON(http.StatusOK, answer.ResBody("200", "", map[string]any{
			"certId":   certID,
			"revision": rev,
		}))
	}
}

// ---------- 查询 ----------

// ListRootCAs GET /spki/ca/roots
func ListRootCAs() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		userID := c.GetString("userId")
		items, err := ListCertsByGenre(GenreRoot, userID)
		if err != nil {
			hlog.Error("ListRootCAs: ", err)
			c.JSON(http.StatusInternalServerError, answer.ResBody("500", err.Error(), ""))
			return
		}
		c.JSON(http.StatusOK, answer.ResBody("200", "", map[string]any{
			"total": len(items),
			"items": items,
		}))
	}
}

// ListIntermediateCAs GET /spki/ca/intermediates
func ListIntermediateCAs() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		userID := c.GetString("userId")
		items, err := ListCertsByGenre(GenreInter, userID)
		if err != nil {
			hlog.Error("ListIntermediateCAs: ", err)
			c.JSON(http.StatusInternalServerError, answer.ResBody("500", err.Error(), ""))
			return
		}
		c.JSON(http.StatusOK, answer.ResBody("200", "", map[string]any{
			"total": len(items),
			"items": items,
		}))
	}
}

// ListLeafCerts GET /spki/cert/leaves
func ListLeafCerts() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		userID := c.GetString("userId")
		items, err := ListCertsByGenre(GenreLeaf, userID)
		if err != nil {
			hlog.Error("ListLeafCerts: ", err)
			c.JSON(http.StatusInternalServerError, answer.ResBody("500", err.Error(), ""))
			return
		}
		c.JSON(http.StatusOK, answer.ResBody("200", "", map[string]any{
			"total": len(items),
			"items": items,
		}))
	}
}

// ListCertVersions GET /spki/cert/:id/versions
func ListCertVersions() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		certID := c.Param("id")
		items, err := ListCertVersionsSvc(certID)
		if err != nil {
			hlog.Error("ListCertVersions: ", err)
			c.JSON(http.StatusInternalServerError, answer.ResBody("500", err.Error(), ""))
			return
		}
		c.JSON(http.StatusOK, answer.ResBody("200", "", map[string]any{
			"total": len(items),
			"items": items,
		}))
	}
}

// ListCert GET /spki/cert?genre=1|2|3
// genre 可选：
//
//	1 = 根 CA
//	2 = 中间 CA
//	3 = 末端证书
//	不传 = 全部
//
// ListCert GET /spki/cert?genre=1&genre=2&genre=3
// 支持多个 genre：
//
//	?genre=1&genre=2  → 查根 CA + 中间 CA
//	?genre=3          → 查末端证书
//	不传               → 全部
type Query struct {
	Genre []int `query:"genre"`
}

func ListCert() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		userID := c.GetString("userId")

		var query Query
		if err := c.BindQuery(&query); err != nil {
			hlog.Error("ListCert bind: ", err)
			c.JSON(http.StatusBadRequest, answer.ResBody("444", "请求体错误: "+err.Error(), ""))
			return
		}
		// genres 为空 → 查全部
		items, err := ListCertsByGenres(query.Genre, userID)
		if err != nil {
			hlog.Error("ListCert: ", err)
			c.JSON(http.StatusInternalServerError, answer.ResBody("500", err.Error(), ""))
			return
		}
		c.JSON(http.StatusOK, answer.ResBody("200", "", map[string]any{
			"total": len(items),
			"items": items,
		}))
	}
}
