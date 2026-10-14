package cacert

import (
	"crypto/x509"
	"errors"
	"fmt"
	"spki/src/models"
	"spki/src/pkg/uuid4"
)

// ---------- 导入 CA ----------

// ImportCAReq 导入 CA 请求
type ImportCAReq struct {
	Title    *string `json:"title"`
	CertPem  string  `json:"certPem"`
	KeyPem   string  `json:"keyPem"`
	IssuerID string  `json:"issuerId"`
}

// ImportCAResp 导入 CA 响应
type ImportCAResp struct {
	CertID  string `json:"certId"`
	Genre   int    `json:"genre"`
	Pathlev int    `json:"pathlev"`
}

// ImportCASvc 导入 CA 证书（根 CA 或中间 CA）
//   - 只允许 IsCA=true 的证书
//   - 中间 CA 必须有父 CA
//   - 只支持 X.509 证书和 PKCS#8 私钥
func ImportCASvc(userID, account string, req *ImportCAReq) (*ImportCAResp, error) {
	// 1. 解析证书
	cert, err := parseSingleCertPEM(req.CertPem)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}

	// 1.5 证书指纹判重
	certFP := calcCertFingerprint(cert)
	if existing, err := models.GetVersionByFingerprint(certFP); err != nil {
		return nil, fmt.Errorf("check cert fingerprint: %w", err)
	} else if existing != nil {
		return nil, fmt.Errorf("certificate already imported: certId=%s", *existing.CertID)
	}

	// 2. 必须是 CA
	if !cert.IsCA {
		return nil, errors.New("only CA certificates can be imported")
	}

	// 3. 判断根 CA 还是中间 CA
	isRoot := cert.Subject.String() == cert.Issuer.String()
	var genre, pathlev int
	if isRoot {
		genre = GenreRoot
		pathlev = PathLevCA
	} else {
		genre = GenreInter
		pathlev = PathLevInter
	}

	// 4. 私钥必填
	if req.KeyPem == "" {
		return nil, errors.New("CA private key is required")
	}
	signer, err := parsePKCS8Key(req.KeyPem)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}

	// 4.5 私钥指纹判重（用公钥指纹代表私钥）
	keyFP, err := calcPubKeyFingerprint(signer)
	if err != nil {
		return nil, fmt.Errorf("calc key fingerprint: %w", err)
	}
	if existing, err := models.GetPrivateKeyByFingerprint(keyFP); err != nil {
		return nil, fmt.Errorf("check key fingerprint: %w", err)
	} else if existing != nil {
		return nil, fmt.Errorf("private key already imported: keyId=%s", existing.KeyID)
	}

	// 5. 校验私钥和证书匹配
	if err := matchCertAndKey(cert, signer); err != nil {
		return nil, err
	}

	// 6. 校验 KeyUsage 有 certSign
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, errors.New("CA certificate must have certSign key usage")
	}

	// 7. 处理 parentId
	var parentID *string
	if !isRoot {
		if req.IssuerID != "" {
			parent, err := models.GetCertificateByCertID(req.IssuerID)
			if err != nil || parent == nil {
				return nil, errors.New("issuerId not found")
			}
			if parent.Genre != GenreRoot && parent.Genre != GenreInter {
				return nil, errors.New("issuer must be a CA")
			}
			parentID = &parent.CertID
		} else {
			parent, err := models.FindCASubject(cert.Issuer.String())
			if err != nil {
				return nil, fmt.Errorf("find parent: %w", err)
			}
			if parent == nil {
				return nil, errors.New("parent CA not found, please specify issuerId")
			}
			parentID = &parent.CertID
		}
	}

	// 8. 加密私钥
	encKey, encPassphrase, err := encryptPrivateKey(signer)
	if err != nil {
		return nil, fmt.Errorf("encrypt key: %w", err)
	}

	// 9. 组装记录
	certID := uuid4.Uuid4Str()
	keyID := uuid4.Uuid4Str()
	now := nowMillis()
	subject := formatSubject(cert.Subject)
	serial := cert.SerialNumber.Text(16)
	eff := cert.NotBefore.UnixMilli()
	exp := cert.NotAfter.UnixMilli()
	state := StateValid
	alarm := int8(0)
	rev := 1

	certRec := models.Certificate{
		CertID:   certID,
		UserID:   userID,
		Title:    req.Title,
		Subject:  &subject,
		ParentID: parentID,
		Pathlev:  pathlev,
		Genre:    genre,
	}
	keyRec := &models.PrivateKey{
		KeyID:       keyID,
		PrivateKey:  encKey,
		Passphrase:  encPassphrase,
		Fingerprint: &keyFP,
		CreateTime:  now,
	}
	version := models.Version{
		Revision:       &rev,
		CertID:         &certID,
		KeyID:          &keyID,
		Serial:         &serial,
		Fingerprint:    &certFP,
		Cert:           strPtr(req.CertPem),
		EffectiveTime:  &eff,
		ExpirationTime: &exp,
		Alarm:          &alarm,
		State:          &state,
	}

	if err := models.SaveCertBundle(certRec, keyRec, version, account); err != nil {
		return nil, err
	}

	return &ImportCAResp{
		CertID:  certID,
		Genre:   genre,
		Pathlev: pathlev,
	}, nil
}
