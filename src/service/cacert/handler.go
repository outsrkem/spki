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
