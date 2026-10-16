package cacert

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"spki/src/models"
	"time"
)

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

	if issuerVer.KeyID == nil {
		return "", errors.New("issuer CA has no private key, cannot sign CRL")
	}

	issuerKeyRec, err := models.GetPrivateKeyByKeyID(*issuerVer.KeyID)
	if err != nil || issuerKeyRec == nil {
		return "", errors.New("issuer key not found")
	}
	issuerCert, err := parseCertPEM(*issuerVer.Cert)
	if err != nil {
		return "", err
	}
	signer, err := decryptPrivateKey(issuerKeyRec.PrivateKey, issuerKeyRec.Passphrase)
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
		Number:                    big.NewInt(time.Now().UnixMilli()),
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
