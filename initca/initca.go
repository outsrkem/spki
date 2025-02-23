package initca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"time"
)

// hash 或 sha256
const subjectKeyIdentifier = "hash"

// generateSubjectKeyId 根据指定的哈希算法生成 SubjectKeyId
func generateSubjectKeyId(caPrivateKey *rsa.PrivateKey, algorithm string) ([]byte, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&caPrivateKey.PublicKey)
	if err != nil {
		panic(err)
	}
	switch algorithm {
	case "hash":
		subjectKeyId := sha1.Sum(pubKeyBytes)
		return subjectKeyId[:], nil
	case "sha256":
		subjectKeyId := sha256.Sum256(pubKeyBytes)
		return subjectKeyId[:], nil
	default:
		return nil, errors.New("unsupported hash algorithm")
	}
}

// InitCA 初始化CA证书
func InitCA(caPrivateKey *rsa.PrivateKey) {
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128-1))
	if err != nil {
		panic(err)
	}

	subjectKeyId, err := generateSubjectKeyId(caPrivateKey, subjectKeyIdentifier)
	if err != nil {
		panic(err)
	}

	caTemplate := x509.Certificate{
		SerialNumber: serialNumber, // 序列号，通常递增
		Subject: pkix.Name{
			CommonName:         "Test CA Root",
			Organization:       []string{"Example Organization"},
			OrganizationalUnit: []string{"Example Unit"},
			Locality:           []string{"City"},
			Province:           []string{"State"},
			Country:            []string{"Country"},
		},
		NotBefore: time.Now(),                                   // 生效时间
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),         // 过期时间，例如1年
		KeyUsage:  x509.KeyUsageCertSign | x509.KeyUsageCRLSign, // 密钥用途
		IsCA:      true,                                         // 表示这是一个CA证书
		// ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, // 扩展用途
		BasicConstraintsValid: true, // 表示这是一个CA证书
		AuthorityKeyId:        subjectKeyId,
		SubjectKeyId:          subjectKeyId,
	}
	fmt.Println(caTemplate.SerialNumber)
	fmt.Println(subjectKeyId)
	// 使用CA私钥和模板生成CA证书
	caBytes, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPrivateKey.PublicKey, caPrivateKey)
	if err != nil {
		panic(err)
	}

	// 将CA证书和私钥写入文件
	certOut, err := os.Create("ca.pem")
	if err != nil {
		panic(err)
	}
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes})
	certOut.Close()

	keyOut, err := os.OpenFile("ca-key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		panic(err)
	}
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caPrivateKey)})
	keyOut.Close()
}
