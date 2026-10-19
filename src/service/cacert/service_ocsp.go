package cacert

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"spki/src/models"
	"time"

	"golang.org/x/crypto/ocsp"
)

// OCSPResponderSvc 处理一次 OCSP 请求
// reqDER 是 DER 编码的 OCSPRequest
// 返回 DER 编码的 OCSPResponse
func OCSPResponderSvc(dao *models.DB, reqDER []byte) ([]byte, error) {
	// 1. 解析 OCSP 请求
	req, err := ocsp.ParseRequest(reqDER)
	if err != nil {
		return nil, fmt.Errorf("parse ocsp request: %w", err)
	}

	// 2. 找到签发该证书的 issuer（证书、签名私钥、issuer 的 certid）
	issuerCert, issuerSigner, issuerID, err := findIssuerForOCSP(dao, req)
	if err != nil {
		return nil, err
	}

	// 3. 查吊销状态：用 issuer 的 certid，不是 serial
	status := ocsp.Good
	var revokedAt time.Time
	revoked, err := dao.ListRevokedByIssuerBySerial(issuerID, req.SerialNumber.Text(16))
	if err != nil {
		return nil, fmt.Errorf("query revocation: %w", err)
	}
	if revoked != nil && revoked.RevocationTime != nil {
		status = ocsp.Revoked
		revokedAt = time.UnixMilli(*revoked.RevocationTime)
	}

	// 4. 构造响应模板
	now := time.Now()
	tpl := &ocsp.Response{
		Status:       status,
		SerialNumber: req.SerialNumber,
		ThisUpdate:   now,
		NextUpdate:   now.Add(24 * time.Hour), // 缓存 24h
	}
	if status == ocsp.Revoked {
		tpl.RevokedAt = revokedAt
		tpl.RevocationReason = ocsp.Unspecified
	}

	// 5. 用 issuer 证书 + 私钥签名（RFC 6960 允许 issuer 直接签）
	respDER, err := ocsp.CreateResponse(issuerCert, issuerCert, *tpl, issuerSigner)
	if err != nil {
		return nil, fmt.Errorf("create ocsp response: %w", err)
	}
	return respDER, nil
}

// findIssuerForOCSP 根据 OCSP 请求找到对应的 issuer 证书、签名私钥和 issuer 的 certid
// 返回值：
//   - issuerCert:   issuer 证书（用于 OCSP 响应里的 ResponderId 和验签基准）
//   - issuerSigner: issuer 私钥（用于签 OCSP 响应）
//   - issuerID:     issuer 的 certid（用于查吊销，对应 pki_certificate.parent_id）
func findIssuerForOCSP(dao *models.DB, req *ocsp.Request) (*x509.Certificate, crypto.Signer, string, error) {
	// 用 serial 找证书记录
	certRec, err := dao.GetCertificateBySerial(req.SerialNumber.Text(16))
	if err != nil || certRec == nil {
		return nil, nil, "", errors.New("certificate not found for serial")
	}

	// 确定 issuer：末端/中间证书用 parent，根 CA 自签
	// 注意：这里必须是 certid，不是 serial
	var issuerID string
	if certRec.ParentID != nil {
		issuerID = *certRec.ParentID
	} else {
		issuerID = certRec.CertID
	}

	issuerVer, err := dao.GetLatestVersion(issuerID)
	if err != nil || issuerVer == nil {
		return nil, nil, "", errors.New("issuer version not found")
	}
	if issuerVer.KeyID == nil {
		return nil, nil, "", errors.New("issuer CA has no private key")
	}

	issuerKeyRec, err := dao.GetPrivateKeyByKeyID(*issuerVer.KeyID)
	if err != nil || issuerKeyRec == nil {
		return nil, nil, "", errors.New("issuer key not found")
	}
	issuerCert, err := parseCertPEM(*issuerVer.Cert)
	if err != nil {
		return nil, nil, "", err
	}
	signer, err := decryptPrivateKey(issuerKeyRec.PrivateKey, issuerKeyRec.Passphrase)
	if err != nil {
		return nil, nil, "", err
	}
	return issuerCert, signer, issuerID, nil
}
