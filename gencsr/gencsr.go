package gencsr

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"spki/profile"
)

func GencsrMain(key *rsa.PrivateKey, profile *profile.Profile) *[]byte {

	csrtemplate := x509.CertificateRequest{
		Subject:        profile.Subject,
		EmailAddresses: profile.EmailAddresses,
		DNSNames:       profile.DNSNames,
		IPAddresses:    profile.IPAddresses,
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &csrtemplate, key)
	if err != nil {
		log.Fatalf("生成证书签名请求时出错: %v", err)
	}

	csrPEM := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	}

	csrPEMBytes := pem.EncodeToMemory(csrPEM)

	// 打印 PEM 格式的 CSR
	fmt.Println(string(csrPEMBytes))
	return &csr
}
