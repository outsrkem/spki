package cacert

import (
	"crypto/x509"
	"errors"
	"fmt"
	"spki/src/models"
	"spki/src/pkg/uuid4"
)

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
	encKey, encPassphrase, err := encryptPrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("encrypt private key: %w", err)
	}
	certPEM := pemEncode("CERTIFICATE", der)

	// 指纹
	certFP := calcCertFingerprint(cert)
	keyFP, err := calcPubKeyFingerprint(key)
	if err != nil {
		return "", fmt.Errorf("calc key fingerprint: %w", err)
	}

	certID := uuid4.Uuid4Str()
	keyID := uuid4.Uuid4Str()
	rev := 1
	now := nowMillis()

	serial := cert.SerialNumber.Text(16)
	eff := cert.NotBefore.UnixMilli()
	exp := cert.NotAfter.UnixMilli()
	subject := formatSubject(cert.Subject)
	state := StateValid
	alarm := int8(0)

	certRec := models.Certificate{
		CertID:   certID,
		UserID:   userID,
		Title:    cfg.Title,
		Subject:  &subject,
		ParentID: nil,
		Pathlev:  PathLevCA,
		Genre:    GenreRoot,
		Alarm:    &alarm,
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
		Cert:           strPtr(string(certPEM)),
		EffectiveTime:  &eff,
		ExpirationTime: &exp,
		State:          &state,
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
	parentSigner, err := decryptPrivateKey(parentKey.PrivateKey, parentKey.Passphrase)
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
	encKey, encPassphrase, err := encryptPrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("encrypt private key: %w", err)
	}
	certPEM := pemEncode("CERTIFICATE", der)

	// 指纹
	certFP := calcCertFingerprint(cert)
	keyFP, err := calcPubKeyFingerprint(key)
	if err != nil {
		return "", fmt.Errorf("calc key fingerprint: %w", err)
	}

	certID := uuid4.Uuid4Str()
	keyID := uuid4.Uuid4Str()
	rev := 1
	now := nowMillis()

	serial := cert.SerialNumber.Text(16)
	eff := cert.NotBefore.UnixMilli()
	exp := cert.NotAfter.UnixMilli()
	subject := formatSubject(cert.Subject)
	state := StateValid
	alarm := int8(0)

	certRec := models.Certificate{
		CertID:   certID,
		UserID:   userID,
		Title:    cfg.Title,
		Subject:  &subject,
		ParentID: &parentID,
		Pathlev:  PathLevInter,
		Genre:    GenreInter,
		Alarm:    &alarm,
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
		Cert:           strPtr(string(certPEM)),
		EffectiveTime:  &eff,
		ExpirationTime: &exp,
		State:          &state,
	}

	if err := models.SaveCertBundle(certRec, keyRec, version, account); err != nil {
		return "", err
	}
	return certID, nil
}
