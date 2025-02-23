package gencert

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"spki/gencsr"
	"spki/profile"
	"spki/src/genkey"
	"time"
)

type any = interface{}

// Gencert 生成末端证书
func Gencert(ca *x509.Certificate, caKey *rsa.PrivateKey) {
	template := profile.Profile{
		Subject: pkix.Name{
			CommonName:         "example.com",
			Organization:       []string{"Example Organization"},
			OrganizationalUnit: []string{"Example Unit"},
			Locality:           []string{"City"},
			Province:           []string{"State"},
			Country:            []string{"Country"},
		},
		EmailAddresses: []string{},
		DNSNames:       []string{"www.example.com", "example.com"},
		IPAddresses:    []net.IP{net.ParseIP("192.168.1.1"), net.ParseIP("192.168.1.2")},
	}
	serverPrivateKey, _ := genkey.GenkeyMain("rsa", 1024)
	csrByte := gencsr.GencsrMain(serverPrivateKey, &template)
	csr, err := x509.ParseCertificateRequest(*csrByte)
	if err != nil {
		fmt.Println("Failed to parse CSR:", err)
		return
	}
	// 验证 CSR 的签名
	err = csr.CheckSignature()
	if err != nil {
		fmt.Println("CSR signature verification failed:", err)
		return
	}

	// publicKey := csr.PublicKey
	// fmt.Println(publicKey)
	// fmt.Println(serverPrivateKey.PublicKey)
	rsaPublicKey, ok := csr.PublicKey.(*rsa.PublicKey)
	if !ok {
		panic("CSR contains a non-RSA public key")
	}
	fmt.Println(rsaPublicKey)
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128-1))
	if err != nil {
		panic(err)
	}
	serverTemplate := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               csr.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth | x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: false,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		EmailAddresses:        csr.EmailAddresses,
		AuthorityKeyId:        ca.SubjectKeyId, // 设置 AuthorityKeyId 为 CA 的 SubjectKeyId
	}

	// 确定公钥类型
	var userPub any // 通用接口，用于存储解析后的公钥
	switch pub := csr.PublicKey.(type) {
	case *rsa.PublicKey:
		userPub = pub
	case *ecdsa.PublicKey:
		userPub = pub
		// 注意：如果你使用的是 ECDSA 公钥，你需要确保 caKey 也是 *ecdsa.PrivateKey 类型
		// 这里没有类型断言，因为我们在后面会根据 userPub 的实际类型来处理
	default:
		fmt.Println("Unknown Public Key Type")
	}
	// userPub := csr.PublicKey.(*rsa.PublicKey)
	cert, err := x509.CreateCertificate(rand.Reader, &serverTemplate, ca, userPub, caKey)
	if err != nil {
		fmt.Println("签署证书失败")
		panic(err)
	}

	certpem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert,
		})

	fmt.Println(string(certpem))
}
