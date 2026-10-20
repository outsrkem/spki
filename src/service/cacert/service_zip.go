package cacert

import (
	"archive/zip"
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"spki/src/models"
	"strings"
	"time"
)

// GetCertZip 打包证书 + 私钥为 ZIP
// 结构：
//
//	{CN}_{YYYYMMDD}_{UnixMilli}.zip
//	└── {CN}_{YYYYMMDD}_{UnixMilli}/
//	    ├── {CN}_{YYYYMMDD}_{UnixMilli}.pem
//	    └── {CN}_{YYYYMMDD}_{UnixMilli}.key
func GetCertZip(dao *models.DB, certID string) ([]byte, string, error) {
	v, err := dao.GetLatestVersion(certID)
	if err != nil || v == nil {
		return nil, "", errors.New("version not found")
	}

	// 1. 解析证书，拿 CN
	cert, err := parseCertPEM(*v.Cert)
	if err != nil {
		return nil, "", fmt.Errorf("parse cert: %w", err)
	}
	cn := cert.Subject.CommonName
	if cn == "" {
		cn = certID
	}
	cn = sanitizeFileName(cn)

	// 2. 生成带日期的文件名前缀
	now := time.Now()
	dateStr := now.Format("20060102")
	ts := now.UnixMilli()
	name := fmt.Sprintf("%s_%s_%d", cn, dateStr, ts)

	// 3. 完整证书链 PEM（末端 + 中间 + 根）
	chainPEM, err := BuildCertChain(dao, certID, true)
	if err != nil {
		return nil, "", fmt.Errorf("build cert chain: %w", err)
	}

	// 4. 私钥 PEM
	var keyPEM string
	if v.KeyID != nil {
		keyRec, err := dao.GetPrivateKeyByKeyID(*v.KeyID)
		if err == nil && keyRec != nil {
			signer, err := decryptPrivateKey(keyRec.PrivateKey, keyRec.Passphrase)
			if err == nil {
				der, err := x509.MarshalPKCS8PrivateKey(signer)
				if err == nil {
					keyPEM = string(pem.EncodeToMemory(&pem.Block{
						Type:  "PRIVATE KEY",
						Bytes: der,
					}))
				}
			}
		}
	}

	// 5. 打 ZIP
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)

	certPath := name + "/" + name + ".pem"
	f, err := zw.Create(certPath)
	if err != nil {
		return nil, "", fmt.Errorf("zip create cert: %w", err)
	}
	if _, err := f.Write([]byte(chainPEM)); err != nil {
		return nil, "", fmt.Errorf("zip write cert: %w", err)
	}

	if keyPEM != "" {
		keyPath := name + "/" + name + ".key"
		f, err := zw.Create(keyPath)
		if err != nil {
			return nil, "", fmt.Errorf("zip create key: %w", err)
		}
		if _, err := f.Write([]byte(keyPEM)); err != nil {
			return nil, "", fmt.Errorf("zip write key: %w", err)
		}
	}

	if err := zw.Close(); err != nil {
		return nil, "", fmt.Errorf("zip close: %w", err)
	}

	zipName := name + ".zip"
	return buf.Bytes(), zipName, nil
}

// sanitizeFileName 过滤文件名非法字符
func sanitizeFileName(s string) string {
	replacer := strings.NewReplacer(
		"/", "_",
		"\\", "_",
		":", "_",
		"*", "_",
		"?", "_",
		"\"", "_",
		"<", "_",
		">", "_",
		"|", "_",
		" ", "_",
	)
	return replacer.Replace(s)
}
