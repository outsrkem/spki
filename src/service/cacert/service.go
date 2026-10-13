package cacert

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	"spki/src/models"
	"spki/src/pkg/uuid4"
)

// nowMillis 毫秒时间戳
func nowMillis() int64 { return time.Now().UnixMilli() }

// ---------- 初始化根 CA ----------

func InitRootCA(userID, account string, cfg *CertConfig) (string, error) {
	if err := validateConfig(cfg); err != nil {
		return "", err
	}

	key, err := createKey(cfg.Key.Algo, cfg.Key.Size)
	if err != nil {
		return "", fmt.Errorf("create key: %w", err)
	}
	der, err := signCert(key, nil, nil, cfg, true)
	if err != nil {
		return "", fmt.Errorf("sign CA: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", fmt.Errorf("parse cert: %w", err)
	}
	keyPEM, err := privateKeyToPEM(key)
	if err != nil {
		return "", fmt.Errorf("key to pem: %w", err)
	}
	certPEM := pemEncode("CERTIFICATE", der)

	certID := uuid4.Uuid4Str()
	keyID := uuid4.Uuid4Str()
	rev := 1
	now := nowMillis()

	serial := cert.SerialNumber.Text(16)
	eff := cert.NotBefore.UnixMilli()
	exp := cert.NotAfter.UnixMilli()
	subject := cert.Subject.String()
	state := StateValid
	alarm := int8(0)

	certRec := models.Certificate{
		CertID:   certID,
		UserID:   userID,
		Title:    cfg.Title,
		State:    &state,
		Subject:  &subject,
		ParentID: nil,
		Pathlev:  PathLevCA,
		Genre:    GenreRoot,
	}
	keyRec := &models.PrivateKey{
		KeyID:      keyID,
		PrivateKey: string(keyPEM),
		CreateTime: now,
	}
	version := models.Version{
		Revision:       &rev,
		CertID:         &certID,
		KeyID:          &keyID,
		Serial:         &serial,
		Cert:           strPtr(string(certPEM)),
		EffectiveTime:  &eff,
		ExpirationTime: &exp,
		Alarm:          &alarm,
	}

	if err := models.SaveCertBundle(certRec, keyRec, version, account); err != nil {
		return "", err
	}
	return certID, nil
}

// ---------- 签发中间 CA ----------

func IssueIntermediateSvc(userID, account, parentID string, cfg *CertConfig) (string, error) {
	if err := validateConfig(cfg); err != nil {
		return "", err
	}

	parent, err := models.GetCertificateByCertID(parentID)
	if err != nil {
		return "", fmt.Errorf("get parent: %w", err)
	}
	if parent == nil {
		return "", errors.New("parent CA not found")
	}
	parentVer, err := models.GetLatestVersion(parentID)
	if err != nil || parentVer == nil {
		return "", errors.New("parent version not found")
	}
	parentKey, err := models.GetPrivateKeyByKeyID(*parentVer.KeyID)
	if err != nil || parentKey == nil {
		return "", errors.New("parent key not found")
	}

	parentCert, err := parseCertPEM(*parentVer.Cert)
	if err != nil {
		return "", err
	}
	parentSigner, err := parseKeySigner(parentKey.PrivateKey)
	if err != nil {
		return "", err
	}

	key, err := createKey(cfg.Key.Algo, cfg.Key.Size)
	if err != nil {
		return "", fmt.Errorf("create key: %w", err)
	}
	der, err := signCert(key, parentCert, parentSigner, cfg, true)
	if err != nil {
		return "", fmt.Errorf("sign intermediate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", err
	}
	keyPEM, err := privateKeyToPEM(key)
	if err != nil {
		return "", err
	}
	certPEM := pemEncode("CERTIFICATE", der)

	certID := uuid4.Uuid4Str()
	keyID := uuid4.Uuid4Str()
	rev := 1
	now := nowMillis()

	serial := cert.SerialNumber.Text(16)
	eff := cert.NotBefore.UnixMilli()
	exp := cert.NotAfter.UnixMilli()
	subject := cert.Subject.String()
	state := StateValid
	alarm := int8(0)

	certRec := models.Certificate{
		CertID:   certID,
		UserID:   userID,
		Title:    cfg.Title,
		State:    &state,
		Subject:  &subject,
		ParentID: &parentID,
		Pathlev:  PathLevInter,
		Genre:    GenreInter,
	}
	keyRec := &models.PrivateKey{
		KeyID:      keyID,
		PrivateKey: string(keyPEM),
		CreateTime: now,
	}
	version := models.Version{
		Revision:       &rev,
		CertID:         &certID,
		KeyID:          &keyID,
		Serial:         &serial,
		Cert:           strPtr(string(certPEM)),
		EffectiveTime:  &eff,
		ExpirationTime: &exp,
		Alarm:          &alarm,
	}

	if err := models.SaveCertBundle(certRec, keyRec, version, account); err != nil {
		return "", err
	}
	return certID, nil
}

// ---------- 签发末端证书 ----------

func IssueEndEntitySvc(userID, account, issuerID string, cfg *CertConfig) (string, error) {
	if err := validateConfig(cfg); err != nil {
		return "", err
	}

	issuer, err := models.GetCertificateByCertID(issuerID)
	if err != nil || issuer == nil {
		return "", errors.New("issuer not found")
	}
	issuerVer, err := models.GetLatestVersion(issuerID)
	if err != nil || issuerVer == nil {
		return "", errors.New("issuer version not found")
	}
	issuerKey, err := models.GetPrivateKeyByKeyID(*issuerVer.KeyID)
	if err != nil || issuerKey == nil {
		return "", errors.New("issuer key not found")
	}
	issuerCert, err := parseCertPEM(*issuerVer.Cert)
	if err != nil {
		return "", err
	}
	issuerSigner, err := parseKeySigner(issuerKey.PrivateKey)
	if err != nil {
		return "", err
	}

	var key crypto.Signer
	var keyPEM []byte
	if cfg.CSRPem == "" {
		key, err = createKey(cfg.Key.Algo, cfg.Key.Size)
		if err != nil {
			return "", err
		}
		keyPEM, err = privateKeyToPEM(key)
		if err != nil {
			return "", err
		}
	}

	der, err := signCert(key, issuerCert, issuerSigner, cfg, false)
	if err != nil {
		return "", fmt.Errorf("sign end entity: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", err
	}
	certPEM := pemEncode("CERTIFICATE", der)

	certID := uuid4.Uuid4Str()
	keyID := uuid4.Uuid4Str()
	rev := 1
	now := nowMillis()

	serial := cert.SerialNumber.Text(16)
	eff := cert.NotBefore.UnixMilli()
	exp := cert.NotAfter.UnixMilli()
	subject := cert.Subject.String()
	state := StateValid
	alarm := int8(0)

	certRec := models.Certificate{
		CertID:   certID,
		UserID:   userID,
		Title:    cfg.Title,
		State:    &state,
		Subject:  &subject,
		ParentID: &issuerID,
		Pathlev:  PathLevLeaf,
		Genre:    GenreLeaf,
		CertReq:  strPtrIf(cfg.CSRPem),
	}
	var keyRec *models.PrivateKey
	if cfg.CSRPem == "" {
		keyRec = &models.PrivateKey{
			KeyID:      keyID,
			PrivateKey: string(keyPEM),
			CreateTime: now,
		}
	}
	version := models.Version{
		Revision:       &rev,
		CertID:         &certID,
		KeyID:          &keyID,
		Serial:         &serial,
		Cert:           strPtr(string(certPEM)),
		EffectiveTime:  &eff,
		ExpirationTime: &exp,
		Alarm:          &alarm,
	}

	if err := models.SaveCertBundle(certRec, keyRec, version, account); err != nil {
		return "", err
	}
	return certID, nil
}

// ---------- 吊销 ----------

func RevokeCertSvc(certID string) error {
	cert, err := models.GetCertificateByCertID(certID)
	if err != nil || cert == nil {
		return errors.New("certificate not found")
	}
	now := nowMillis()
	return models.RevokeCertTx(certID, StateRevoked, now)
}

// ---------- 删除 ----------

func DeleteCertSvc(certID string) error {
	return models.DeleteCertTx(certID)
}

// ---------- 拼链 ----------

func BuildCAChain(certID string, includeRoot bool) (string, error) {
	cur, err := models.GetCertificateByCertID(certID)
	if err != nil || cur == nil {
		return "", errors.New("certificate not found")
	}
	var out string
	for cur != nil {
		if cur.Pathlev == PathLevCA && !includeRoot {
			break
		}
		v, err := models.GetLatestVersion(cur.CertID)
		if err != nil || v == nil {
			break
		}
		out += *v.Cert
		if cur.ParentID == nil {
			break
		}
		cur, err = models.GetCertificateByCertID(*cur.ParentID)
		if err != nil {
			break
		}
	}
	return out, nil
}

func BuildCertChain(certID string, includeRoot bool) (string, error) {
	cert, err := models.GetCertificateByCertID(certID)
	if err != nil || cert == nil {
		return "", errors.New("certificate not found")
	}
	v, err := models.GetLatestVersion(certID)
	if err != nil || v == nil {
		return "", errors.New("version not found")
	}
	chain := *v.Cert
	if cert.ParentID != nil {
		caChain, err := BuildCAChain(*cert.ParentID, includeRoot)
		if err != nil {
			return "", err
		}
		chain += caChain
	}
	return chain, nil
}

// ---------- CRL ----------

func BuildCRL(issuerID string) (string, error) {
	issuer, err := models.GetCertificateByCertID(issuerID)
	if err != nil || issuer == nil {
		return "", errors.New("issuer not found")
	}
	issuerVer, err := models.GetLatestVersion(issuerID)
	if err != nil || issuerVer == nil {
		return "", errors.New("issuer version not found")
	}
	issuerKeyRec, err := models.GetPrivateKeyByKeyID(*issuerVer.KeyID)
	if err != nil || issuerKeyRec == nil {
		return "", errors.New("issuer key not found")
	}
	issuerCert, err := parseCertPEM(*issuerVer.Cert)
	if err != nil {
		return "", err
	}
	signer, err := parseKeySigner(issuerKeyRec.PrivateKey)
	if err != nil {
		return "", err
	}

	revoked, err := models.ListRevokedByIssuer(issuerID)
	if err != nil {
		return "", err
	}

	var entries []x509.RevocationListEntry
	for _, v := range revoked {
		if v.Serial == nil || v.RevocationTime == nil {
			continue
		}
		serial := new(big.Int)
		serial.SetString(*v.Serial, 16)
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: time.UnixMilli(*v.RevocationTime),
		})
	}

	template := &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                time.Now(),
		NextUpdate:                time.Now().Add(7 * 24 * time.Hour),
		RevokedCertificateEntries: entries,
	}
	der, err := x509.CreateRevocationList(rand.Reader, template, issuerCert, signer)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})), nil
}
