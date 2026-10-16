package cacert

import (
	"context"
	"net/http"

	"spki/src/models"
	"spki/src/pkg/answer"
	"spki/src/pkg/common"

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
			Issuer struct {
				ID string `json:"id"`
			} `json:"issuer"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, answer.ResBody("444", err.Error(), ""))
			return
		}
		if req.Issuer.ID == "" {
			c.JSON(http.StatusBadRequest, answer.ResBody("444", "issuer.id is required", ""))
			return
		}
		userID := c.GetString("userId")
		account := c.GetString("account")

		certID, err := IssueIntermediateSvc(userID, account, req.Issuer.ID, &req.CertConfig)
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
			Issuer struct {
				ID string `json:"id"`
			} `json:"issuer"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, answer.ResBody("444", err.Error(), ""))
			return
		}
		if req.Issuer.ID == "" {
			c.JSON(http.StatusBadRequest, answer.ResBody("444", "issuer.id is required", ""))
			return
		}
		userID := c.GetString("userId")
		account := c.GetString("account")

		certID, err := IssueEndEntitySvc(userID, account, req.Issuer.ID, &req.CertConfig)
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
// 参数：
//
//	includeRoot=true|false  链里是否包含根 CA，默认 true
//	onlyRoot=true|false     只返回根 CA 的 PEM，默认 false
//
// 用法：
//
//	/chain                    完整链（末端 + 中间 + 根）
//	/chain?includeRoot=false  不含根
//	/chain?onlyRoot=true      只返回根 CA
func ExportCertChain() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		certID := c.Param("id")
		includeRoot := c.DefaultQuery("includeRoot", "true") != "false"
		onlyRoot := c.DefaultQuery("onlyRoot", "false") == "true"

		var chain string
		var err error

		if onlyRoot {
			chain, err = BuildRootPEM(certID)
		} else {
			chain, err = BuildCertChain(certID, includeRoot)
		}
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
			Expiry Expiry `json:"expiry"`
		}
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, answer.ResBody("444", "请求体错误: "+err.Error(), ""))
			return
		}
		if req.Expiry.Years == 0 && req.Expiry.Months == 0 && req.Expiry.Days == 0 {
			c.JSON(http.StatusBadRequest, answer.ResBody("444", "expiry is required", ""))
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

// ListCert GET /spki/cert?genre=1&genre=2
// 支持多个 genre：
//
//	?genre=1&genre=2  → 查根 CA + 中间 CA
//	?genre=3          → 查末端证书
//	不传              → 全部
func ListCert() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		userID := c.GetString("userId")

		var query Query
		if err := c.BindQuery(&query); err != nil {
			hlog.Error("ListCert bind: ", err)
			c.JSON(http.StatusBadRequest, answer.ResBody("444", "参数错误: "+err.Error(), ""))
			return
		}

		// 校验 genre 范围
		for _, g := range query.Genre {
			if g < 1 || g > 3 {
				c.JSON(http.StatusBadRequest, answer.ResBody("444", "genre must be 1/2/3", ""))
				return
			}
		}
		offset, limit, err := common.GetPagingQuery(c)
		if err != nil {
			c.JSON(http.StatusBadRequest, answer.ResBody("444", "参数错误", ""))
			return
		}

		hasKey := -1
		if query.HasKey != nil {
			if *query.HasKey != 0 && *query.HasKey != 1 {
				c.JSON(http.StatusBadRequest, answer.ResBody("444", "hasKey must be 0 or 1", ""))
				return
			}
			hasKey = *query.HasKey
		}
		count := int64(0)
		items, err := ListCertsByGenres(offset, limit, &count, query.Genre, hasKey, userID)
		if err != nil {
			hlog.Error("ListCert: ", err)
			c.JSON(http.StatusInternalServerError, answer.ResBody("500", err.Error(), ""))
			return
		}

		payload := map[string]any{
			"page_info": answer.SetPageInfo(offset, limit, count),
			"items":     items,
		}
		c.JSON(http.StatusOK, answer.ResBody(answer.EcodeOK, nil, payload))

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

// FindRootCA GET /spki/cert/:id/root
// 从任意证书向上找到根 CA
func FindRootCA() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		certID := c.Param("id")
		info, err := FindRootCASvc(certID)
		if err != nil {
			hlog.Error("FindRootCA: ", err)
			c.JSON(http.StatusInternalServerError, answer.ResBody("500", err.Error(), ""))
			return
		}
		c.JSON(http.StatusOK, answer.ResBody("200", "", info))
	}
}

// ---------- Query 结构体 ----------

// Query 查询参数
type Query struct {
	Genre  []int `query:"genre"`
	HasKey *int  `query:"hasKey"`
}

func ExportCertBundle() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		certID := c.Param("id")

		cert, err := models.GetCertificateByCertID(certID)
		if err != nil || cert == nil {
			c.JSON(http.StatusNotFound, answer.ResBody("404", "certificate not found", ""))
			return
		}
		if cert.Genre != GenreLeaf {
			c.JSON(http.StatusForbidden, answer.ResBody("403", "CA private key cannot be downloaded", ""))
			return
		}

		zipData, zipName, err := GetCertZip(certID)
		if err != nil {
			hlog.Error("ExportCertBundle: ", err)
			c.JSON(http.StatusInternalServerError, answer.ResBody("500", err.Error(), ""))
			return
		}

		c.Header("Content-Disposition", "attachment; filename=\""+zipName+"\"")
		c.Data(http.StatusOK, "application/zip", zipData)
	}
}

// ---------- 导入 CA ----------

// ImportCA POST /spki/ca/import
// 只导入根 CA 或中间 CA
func ImportCA() app.HandlerFunc {
	return func(ctx context.Context, c *app.RequestContext) {
		var req ImportCAReq
		if err := c.BindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, answer.ResBody("444", "请求体错误: "+err.Error(), ""))
			return
		}
		if req.CertPem == "" {
			c.JSON(http.StatusBadRequest, answer.ResBody("444", "certPem is required", ""))
			return
		}

		userID := c.GetString("userId")
		account := c.GetString("account")

		resp, err := ImportCASvc(userID, account, &req)
		if err != nil {
			hlog.Error("ImportCA: ", err)
			c.JSON(http.StatusInternalServerError, answer.ResBody("500", err.Error(), ""))
			return
		}
		c.JSON(http.StatusCreated, answer.ResBody("200", "", resp))
	}
}
