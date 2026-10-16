package cacert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
	"spki/src/models"
)

// ---------- 续签 ----------

// RenewCertSvc 续签统一入口
//   - 根 CA（parent_id == NULL）→ 自签名
//   - 中间 CA / 末端证书 → 上级 CA 签
func RenewCertSvc(dao *models.DB, certID string, expiry Expiry) (int, error) {
	if expiry.Years == 0 && expiry.Months == 0 && expiry.Days == 0 {
		return 0, errors.New("expiry is required")
	}

	cert, err := dao.GetCertificateByCertID(certID)
	if err != nil {
		return 0, fmt.Errorf("get certificate: %w", err)
	}
	if cert == nil {
		return 0, errors.New("certificate not found")
	}

	// 根 CA：自签名
	if cert.ParentID == nil {
		return renewCert(dao, certID, expiry, true, true)
	}

	// 中间 CA 或末端证书：上级签
	isCA := cert.Genre == GenreInter
	return renewCert(dao, certID, expiry, isCA, false)
}

// renewCert 续签核心
//
//	selfSign = true  → 自签名（根 CA）
//	selfSign = false → 上级签（中间 CA / 末端证书）
//	isCA     = true  → CA 证书
//	isCA     = false → 末端证书
func renewCert(dao *models.DB, certID string, expiry Expiry, isCA, selfSign bool) (int, error) {
	// 1. 查原证书
	cert, err := dao.GetCertificateByCertID(certID)
	if err != nil || cert == nil {
		return 0, errors.New("certificate not found")
	}

	// 2. 查原证书最新版本
	oldVer, err := dao.GetLatestVersion(certID)
	if err != nil || oldVer == nil {
		return 0, errors.New("version not found")
	}
	if oldVer.KeyID == nil {
		return 0, errors.New("old version has no key (CSR mode not supported)")
	}

	// 3. 复用旧私钥
	oldKey, err := dao.GetPrivateKeyByKeyID(*oldVer.KeyID)
	if err != nil || oldKey == nil {
		return 0, errors.New("old private key not found")
	}
	signer, err := decryptPrivateKey(oldKey.PrivateKey, oldKey.Passphrase)
	if err != nil {
		return 0, fmt.Errorf("decrypt old key: %w", err)
	}

	// 4. 解析旧证书，还原配置
	oldCert, err := parseCertPEM(*oldVer.Cert)
	if err != nil {
		return 0, err
	}
	cfg := buildRenewConfig(cert, oldCert, expiry, isCA)

	// 5. 取签发者
	var parentCert *x509.Certificate
	var parentSigner crypto.Signer

	if !selfSign {
		issuer, err := dao.GetCertificateByCertID(*cert.ParentID)
		if err != nil || issuer == nil {
			return 0, errors.New("issuer not found")
		}
		issuerVer, err := dao.GetLatestVersion(*cert.ParentID)
		if err != nil || issuerVer == nil {
			return 0, errors.New("issuer version not found")
		}

		if issuerVer.KeyID == nil {
			return 0, errors.New("issuer CA has no private key, cannot sign")
		}

		issuerKey, err := dao.GetPrivateKeyByKeyID(*issuerVer.KeyID)
		if err != nil || issuerKey == nil {
			return 0, errors.New("issuer key not found")
		}
		parentCert, err = parseCertPEM(*issuerVer.Cert)
		if err != nil {
			return 0, err
		}
		parentSigner, err = decryptPrivateKey(issuerKey.PrivateKey, issuerKey.Passphrase)
		if err != nil {
			return 0, err
		}
	}

	// 6. 重新签一张
	der, err := signCert(signer, parentCert, parentSigner, cfg, isCA)
	if err != nil {
		return 0, fmt.Errorf("sign renew: %w", err)
	}
	newCert, err := x509.ParseCertificate(der)
	if err != nil {
		return 0, err
	}
	certPEM := pemEncode("CERTIFICATE", der)

	certFP := calcCertFingerprint(newCert)

	// 7. 取下一个 revision
	maxRev, err := dao.GetMaxRevision(certID)
	if err != nil {
		return 0, err
	}
	rev := maxRev + 1

	// 8. 组装新 version
	serial := newCert.SerialNumber.Text(16)
	eff := newCert.NotBefore.UnixMilli()
	exp := newCert.NotAfter.UnixMilli()
	state := StateValid

	newVer := models.Version{
		Revision:       &rev,
		CertID:         &certID,
		KeyID:          oldVer.KeyID,
		Serial:         &serial,
		Fingerprint:    &certFP,
		Cert:           strPtr(string(certPEM)),
		EffectiveTime:  &eff,
		ExpirationTime: &exp,
		State:          &state,
	}

	// 9. 事务写入
	if err := dao.SaveVersionWithKey(nil, newVer); err != nil {
		return 0, err
	}
	return rev, nil
}

// buildRenewConfig 从旧证书还原续期配置
func buildRenewConfig(cert *models.Certificate, oldCert *x509.Certificate, expiry Expiry, isCA bool) *CertConfig {
	cfg := &CertConfig{
		Title:                cert.Title,
		Expiry:               expiry,
		SubjectKeyIdentifier: "sha256",
		Names: Names{
			CN: oldCert.Subject.CommonName,
		},
	}

	cfg.Key = inferKeySpec(oldCert)

	if len(oldCert.Subject.Organization) > 0 {
		cfg.Names.O = oldCert.Subject.Organization[0]
	}
	if len(oldCert.Subject.OrganizationalUnit) > 0 {
		cfg.Names.OU = oldCert.Subject.OrganizationalUnit[0]
	}
	if len(oldCert.Subject.Country) > 0 {
		cfg.Names.C = &oldCert.Subject.Country[0]
	}
	if len(oldCert.Subject.Locality) > 0 {
		cfg.Names.L = &oldCert.Subject.Locality[0]
	}
	if len(oldCert.Subject.Province) > 0 {
		cfg.Names.ST = &oldCert.Subject.Province[0]
	}

	cfg.KeyUsage = keyUsageToStrings(oldCert.KeyUsage)

	if !isCA {
		cfg.ExtKeyUsage = extKeyUsageToStrings(oldCert.ExtKeyUsage)
		cfg.AltNames.DNS = oldCert.DNSNames
		cfg.AltNames.Email = oldCert.EmailAddresses
		for _, ip := range oldCert.IPAddresses {
			cfg.AltNames.IP = append(cfg.AltNames.IP, ip.String())
		}
		for _, u := range oldCert.URIs {
			cfg.AltNames.URI = append(cfg.AltNames.URI, u.String())
		}
	}

	if isCA && oldCert.MaxPathLen >= 0 {
		pl := oldCert.MaxPathLen
		cfg.PathLen = &pl
	}

	return cfg
}

// inferKeySpec 从旧证书的公钥推断算法和长度
func inferKeySpec(cert *x509.Certificate) KeySpec {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return KeySpec{Algo: "rsa", Size: pub.N.BitLen()}
	case *ecdsa.PublicKey:
		return KeySpec{Algo: "ecdsa", Size: pub.Curve.Params().BitSize}
	case ed25519.PublicKey:
		return KeySpec{Algo: "ed25519", Size: 0}
	default:
		return KeySpec{Algo: "ecdsa", Size: 256}
	}
}

// keyUsageToStrings x509.KeyUsage → []string
func keyUsageToStrings(ku x509.KeyUsage) []string {
	var out []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
		out = append(out, "digitalSignature")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		out = append(out, "contentCommitment") // parseKeyUsage 接受 contentCommitment/nonRepudiation
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		out = append(out, "keyEncipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		out = append(out, "dataEncipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		out = append(out, "keyAgreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		out = append(out, "keyCertSign") // ← 修复：之前误写成 certSign
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		out = append(out, "crlSign")
	}
	if ku&x509.KeyUsageEncipherOnly != 0 {
		out = append(out, "encipherOnly")
	}
	if ku&x509.KeyUsageDecipherOnly != 0 {
		out = append(out, "decipherOnly")
	}
	return out
}
