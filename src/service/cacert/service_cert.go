package cacert

import (
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"spki/src/models"
	"spki/src/pkg/uuid4"
)

// ---------- 签发末端证书 ----------

func IssueEndEntitySvc(dao *models.DB, issuerID string, cfg *CertConfig) (string, error) {
	if err := validateConfig(cfg); err != nil {
		return "", err
	}

	issuer, err := dao.GetCertificateByCertID(issuerID)
	if err != nil || issuer == nil {
		return "", errors.New("issuer not found")
	}
	issuerVer, err := dao.GetLatestVersion(issuerID)
	if err != nil || issuerVer == nil {
		return "", errors.New("issuer version not found")
	}

	if issuerVer.KeyID == nil {
		return "", errors.New("issuer CA has no private key, cannot sign")
	}

	issuerKey, err := dao.GetPrivateKeyByKeyID(*issuerVer.KeyID)
	if err != nil || issuerKey == nil {
		return "", errors.New("issuer key not found")
	}
	issuerCert, err := parseCertPEM(*issuerVer.Cert)
	if err != nil {
		return "", err
	}
	issuerSigner, err := decryptPrivateKey(issuerKey.PrivateKey, issuerKey.Passphrase)
	if err != nil {
		return "", err
	}

	var key crypto.Signer
	var encKey string
	var encPassphrase string
	var keyFP string
	var keyIDPtr *string

	if cfg.CSRPem == "" {
		key, err = createKey(cfg.Key.Algo, cfg.Key.Size)
		if err != nil {
			return "", err
		}
		encKey, encPassphrase, err = encryptPrivateKey(key)
		if err != nil {
			return "", fmt.Errorf("encrypt private key: %w", err)
		}
		keyFP, err = calcPubKeyFingerprint(key)
		if err != nil {
			return "", fmt.Errorf("calc key fingerprint: %w", err)
		}
		keyID := uuid4.Uuid4Str()
		keyIDPtr = &keyID
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

	certFP := calcCertFingerprint(cert)

	certID := uuid4.Uuid4Str()
	rev := 1
	now := nowMillis()

	serial := cert.SerialNumber.Text(16)
	eff := cert.NotBefore.UnixMilli()
	exp := cert.NotAfter.UnixMilli()
	subject := formatSubject(cert.Subject)
	state := StateValid
	hasKey := int8(0)
	if cfg.CSRPem == "" {
		hasKey = 1
	}

	certRec := models.Certificate{
		CertID:   certID,
		Title:    cfg.Title,
		Subject:  &subject,
		ParentID: &issuerID,
		Pathlev:  PathLevLeaf,
		Genre:    GenreLeaf,
		HasKey:   hasKey,
		CertReq:  strPtrIf(cfg.CSRPem),
	}

	var keyRec *models.PrivateKey
	if cfg.CSRPem == "" {
		keyRec = &models.PrivateKey{
			KeyID:       *keyIDPtr,
			PrivateKey:  encKey,
			Passphrase:  encPassphrase,
			Fingerprint: &keyFP,
			CreateTime:  now,
		}
	}

	version := models.Version{
		Revision:       &rev,
		CertID:         &certID,
		KeyID:          keyIDPtr,
		Serial:         &serial,
		Fingerprint:    &certFP,
		Cert:           strPtr(string(certPEM)),
		EffectiveTime:  &eff,
		ExpirationTime: &exp,
		State:          &state,
	}

	if err := dao.SaveCertBundle(certRec, keyRec, version); err != nil {
		return "", err
	}
	return certID, nil
}
