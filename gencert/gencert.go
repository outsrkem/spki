package gencert

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"

	"spki/gencsr"
	"spki/profile"
	"spki/src/genkey"
)

// Options 签发末端证书的参数
type Options struct {
	// 主题信息
	Subject pkix.Name

	// 扩展
	DNSNames       []string
	IPAddresses    []net.IP
	EmailAddresses []string

	// 有效期
	Validity time.Duration

	// 服务端私钥算法与长度
	KeyAlgo string
	KeySize int
}

// Result 签发结果
type Result struct {
	CertificatePEM []byte // 证书 PEM
	PrivateKeyPEM  []byte // 服务端私钥 PEM（PKCS#8）
	CSR            *x509.CertificateRequest
}

// DefaultOptions 返回一个示例配置
func DefaultOptions() *Options {
	return &Options{
		Subject: pkix.Name{
			CommonName:         "example.com",
			Organization:       []string{"Example Organization"},
			OrganizationalUnit: []string{"Example Unit"},
			Locality:           []string{"City"},
			Province:           []string{"State"},
			Country:            []string{"Country"},
		},
		DNSNames:       []string{"www.example.com", "example.com"},
		IPAddresses:    []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("192.168.1.2")},
		EmailAddresses: []string{},
		Validity:       365 * 24 * time.Hour,
		KeyAlgo:        "rsa",
		KeySize:        2048,
	}
}

// randomSerialNumber 生成一个 128 位正整数序列号
func randomSerialNumber() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	return serial, nil
}

// Gencert 使用 CA 证书和私钥签发一张末端证书
//
//	ca     : CA 证书（用于签发）
//	caKey  : CA 私钥（*rsa.PrivateKey / *ecdsa.PrivateKey / ed25519.PrivateKey）
//	opts   : 签发参数，若为 nil 使用 DefaultOptions()
func Gencert(ca *x509.Certificate, caKey any, opts *Options) (*Result, error) {
	if ca == nil {
		return nil, errors.New("ca certificate is nil")
	}
	if caKey == nil {
		return nil, errors.New("ca private key is nil")
	}
	if opts == nil {
		opts = DefaultOptions()
	}
	if opts.Validity <= 0 {
		return nil, fmt.Errorf("validity must be > 0, got %s", opts.Validity)
	}
	if opts.KeyAlgo == "" {
		opts.KeyAlgo = "rsa"
	}
	if opts.KeySize == 0 {
		opts.KeySize = 2048
	}

	// 1. 生成服务端私钥
	serverPrivateKey, err := genkey.CreateKey(opts.KeyAlgo, opts.KeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to create server key: %w", err)
	}

	// 2. 生成 CSR
	template := profile.Profile{
		Subject:        opts.Subject,
		EmailAddresses: opts.EmailAddresses,
		DNSNames:       opts.DNSNames,
		IPAddresses:    opts.IPAddresses,
	}
	csrByte := gencsr.GencsrMain(serverPrivateKey, &template)
	if csrByte == nil {
		return nil, errors.New("GencsrMain returned nil")
	}

	csr, err := x509.ParseCertificateRequest(*csrByte)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature verification failed: %w", err)
	}

	// 3. 序列号
	serialNumber, err := randomSerialNumber()
	if err != nil {
		return nil, err
	}

	// 4. 证书模板
	now := time.Now()
	serverTemplate := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      csr.Subject,

		// 时钟偏移容忍
		NotBefore: now.Add(-5 * time.Minute),
		NotAfter:  now.Add(opts.Validity),

		KeyUsage: x509.KeyUsageDigitalSignature |
			x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDataEncipherment,

		// 修复：原来用了按位或 |，会把两个枚举值合并成一个无效值
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},

		BasicConstraintsValid: true,
		IsCA:                  false,

		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
		EmailAddresses: csr.EmailAddresses,

		// 指向签发者
		AuthorityKeyId: ca.SubjectKeyId,
	}

	// 5. 确定公钥类型（兼容 RSA / ECDSA / Ed25519）
	switch csr.PublicKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		// ok
	default:
		return nil, fmt.Errorf("unsupported CSR public key type: %T", csr.PublicKey)
	}

	// 6. 签名
	certDER, err := x509.CreateCertificate(
		rand.Reader,
		&serverTemplate,
		ca,
		csr.PublicKey,
		caKey,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}

	// 7. 编码 PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyPEM, err := genkey.PrivateKeyToPEM(serverPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode server private key: %w", err)
	}

	return &Result{
		CertificatePEM: certPEM,
		PrivateKeyPEM:  keyPEM,
		CSR:            csr,
	}, nil
}
