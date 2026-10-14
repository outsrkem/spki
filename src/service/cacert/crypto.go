package cacert

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
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
	"net"
	"strings"
	"time"
)

// ---------- 私钥 ----------

func createKey(algo string, size int) (crypto.Signer, error) {
	switch algo {
	case "rsa":
		if size < 2048 {
			return nil, fmt.Errorf("RSA size must be >= 2048, got %d", size)
		}
		return rsa.GenerateKey(rand.Reader, size)
	case "ecdsa":
		var curve elliptic.Curve
		switch size {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			return nil, fmt.Errorf("unsupported ECDSA size: %d", size)
		}
		return ecdsa.GenerateKey(curve, rand.Reader)
	case "ed25519":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		return priv, nil
	default:
		return nil, fmt.Errorf("unsupported algo: %s", algo)
	}
}

func privateKeyToPEM(key any) ([]byte, error) {
	if key == nil {
		return nil, errors.New("private key is nil")
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

func getPublicKey(privateKey any) (any, error) {
	switch k := privateKey.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey), nil
	default:
		return nil, fmt.Errorf("unsupported key type: %T", privateKey)
	}
}

// ---------- SKI / 序列号 ----------

func generateSubjectKeyID(pubDER []byte, algo string) ([]byte, error) {
	switch algo {
	case "sha1", "hash":
		s := sha1.Sum(pubDER)
		return s[:], nil
	case "sha256":
		s := sha256.Sum256(pubDER)
		return s[:], nil
	default:
		return nil, fmt.Errorf("unsupported SKI algo: %s", algo)
	}
}

func randomSerial() (*big.Int, error) {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	s, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	if s.Sign() == 0 {
		s.SetInt64(1)
	}
	return s, nil
}

// ---------- 校验 ----------

func validateConfig(cfg *CertConfig) error {
	if cfg.Names.CN == "" {
		return errors.New("names.CN is required")
	}
	if cfg.Names.O == "" {
		return errors.New("names.O is required")
	}
	if cfg.Names.OU == "" {
		return errors.New("names.OU is required")
	}
	if cfg.Expiry <= 0 {
		return fmt.Errorf("expiry must be > 0, got %d", cfg.Expiry)
	}
	if cfg.SubjectKeyIdentifier == "hash" {
		cfg.SubjectKeyIdentifier = "sha1"
	}
	switch cfg.SubjectKeyIdentifier {
	case "sha1", "sha256":
	default:
		return fmt.Errorf("unsupported subjectKeyIdentifier: %q", cfg.SubjectKeyIdentifier)
	}
	switch cfg.Key.Algo {
	case "rsa":
		if cfg.Key.Size < 2048 {
			return fmt.Errorf("RSA key size must be >= 2048, got %d", cfg.Key.Size)
		}
	case "ecdsa":
		switch cfg.Key.Size {
		case 256, 384, 521:
		default:
			return fmt.Errorf("ECDSA key size must be 256/384/521, got %d", cfg.Key.Size)
		}
	case "ed25519":
	default:
		return fmt.Errorf("unsupported key algorithm: %q", cfg.Key.Algo)
	}
	return nil
}

func parseKeyUsage(list []string, isCA bool) (x509.KeyUsage, error) {
	if len(list) == 0 {
		if isCA {
			return x509.KeyUsageCertSign | x509.KeyUsageCRLSign, nil
		}
		return x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, nil
	}
	var ku x509.KeyUsage
	for _, s := range list {
		switch s {
		case "digitalSignature":
			ku |= x509.KeyUsageDigitalSignature
		case "keyEncipherment":
			ku |= x509.KeyUsageKeyEncipherment
		case "certSign", "keyCertSign":
			ku |= x509.KeyUsageCertSign
		case "crlSign":
			ku |= x509.KeyUsageCRLSign
		default:
			return 0, fmt.Errorf("unsupported keyUsage: %s", s)
		}
	}
	return ku, nil
}

func parseExtKeyUsage(list []string) ([]x509.ExtKeyUsage, error) {
	var out []x509.ExtKeyUsage
	for _, s := range list {
		switch s {
		case "serverAuth":
			out = append(out, x509.ExtKeyUsageServerAuth)
		case "clientAuth":
			out = append(out, x509.ExtKeyUsageClientAuth)
		case "codeSigning":
			out = append(out, x509.ExtKeyUsageCodeSigning)
		case "emailProtection":
			out = append(out, x509.ExtKeyUsageEmailProtection)
		case "timeStamping":
			out = append(out, x509.ExtKeyUsageTimeStamping)
		case "ocspSigning":
			out = append(out, x509.ExtKeyUsageOCSPSigning)
		default:
			return nil, fmt.Errorf("unsupported extKeyUsage: %s", s)
		}
	}
	return out, nil
}

// ---------- 签发核心 ----------

func buildSubject(n Names) pkix.Name {
	subject := pkix.Name{
		CommonName:         n.CN,
		Organization:       []string{n.O},
		OrganizationalUnit: []string{n.OU},
	}
	if n.C != nil && *n.C != "" {
		subject.Country = []string{*n.C}
	}
	if n.L != nil && *n.L != "" {
		subject.Locality = []string{*n.L}
	}
	if n.ST != nil && *n.ST != "" {
		subject.Province = []string{*n.ST}
	}
	return subject
}

// signCert 通用签发：
//   - parentCert == nil 时自签名（根 CA）
//   - parentCert != nil 时由 parent 签发（中间 CA / 末端证书）
func signCert(subjectKey any, parentCert *x509.Certificate, parentSigner crypto.Signer, cfg *CertConfig, isCA bool) ([]byte, error) {
	if cfg == nil {
		return nil, errors.New("config is nil")
	}
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	// 公钥：优先 CSR
	var pub any
	if cfg.CSRPem != "" {
		block, _ := pem.Decode([]byte(cfg.CSRPem))
		if block == nil {
			return nil, errors.New("invalid CSR PEM")
		}
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse CSR: %w", err)
		}
		if err := csr.CheckSignature(); err != nil {
			return nil, fmt.Errorf("CSR signature invalid: %w", err)
		}
		pub = csr.PublicKey
	} else {
		if subjectKey == nil {
			return nil, errors.New("subject key is nil")
		}
		var err error
		pub, err = getPublicKey(subjectKey)
		if err != nil {
			return nil, err
		}
	}

	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	ski, err := generateSubjectKeyID(pubDER, cfg.SubjectKeyIdentifier)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}

	subject := buildSubject(cfg.Names)

	ku, err := parseKeyUsage(cfg.KeyUsage, isCA)
	if err != nil {
		return nil, err
	}
	eku, err := parseExtKeyUsage(cfg.ExtKeyUsage)
	if err != nil {
		return nil, err
	}

	ips := make([]net.IP, 0, len(cfg.IPAddresses))
	for _, s := range cfg.IPAddresses {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP: %s", s)
		}
		ips = append(ips, ip)
	}

	now := time.Now()
	tpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(time.Duration(cfg.Expiry) * 24 * time.Hour),
		KeyUsage:              ku,
		ExtKeyUsage:           eku,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		SubjectKeyId:          ski,
		DNSNames:              cfg.DNSNames,
		IPAddresses:           ips,
		EmailAddresses:        cfg.EmailAddresses,
	}
	if isCA {
		tpl.AuthorityKeyId = ski
		if cfg.PathLen != nil {
			tpl.MaxPathLen = *cfg.PathLen
			tpl.MaxPathLenZero = *cfg.PathLen == 0
		}
	}

	// 自签名
	if parentCert == nil {
		signer, ok := subjectKey.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("subject key does not implement crypto.Signer: %T", subjectKey)
		}
		tpl.AuthorityKeyId = ski
		return x509.CreateCertificate(rand.Reader, &tpl, &tpl, pub, signer)
	}

	// 父签
	tpl.AuthorityKeyId = parentCert.SubjectKeyId
	if parentSigner == nil {
		return nil, errors.New("parent signer is nil")
	}
	return x509.CreateCertificate(rand.Reader, &tpl, parentCert, pub, parentSigner)
}

// ---------- 解析工具 ----------

func parseCertPEM(pemStr string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("invalid cert PEM")
	}
	return x509.ParseCertificate(block.Bytes)
}

func parseKeySigner(pemStr string) (crypto.Signer, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("invalid key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("private key does not implement crypto.Signer: %T", key)
	}
	return signer, nil
}

func pemEncode(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}

func strPtr(s string) *string { return &s }

func strPtrIf(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// formatSubject 把 pkix.Name 转成 OpenSSL -subj 风格
// 输出：/C=CN/O=PrivateSign/OU=PrivateSign/CN=AAA PrivateSign Root CA
func formatSubject(n pkix.Name) string {
	var b strings.Builder

	// C（可能有多个）
	for _, c := range n.Country {
		b.WriteString("/C=")
		b.WriteString(c)
	}
	// ST
	for _, st := range n.Province {
		b.WriteString("/ST=")
		b.WriteString(st)
	}
	// L
	for _, l := range n.Locality {
		b.WriteString("/L=")
		b.WriteString(l)
	}
	// O
	for _, o := range n.Organization {
		b.WriteString("/O=")
		b.WriteString(o)
	}
	// OU
	for _, ou := range n.OrganizationalUnit {
		b.WriteString("/OU=")
		b.WriteString(ou)
	}
	// CN
	if n.CommonName != "" {
		b.WriteString("/CN=")
		b.WriteString(n.CommonName)
	}

	return b.String()
}

// ---------- 导入辅助 ----------

// parseSingleCertPEM 解析单个 X.509 证书 PEM
// 只接受 CERTIFICATE 类型，拒绝证书链
func parseSingleCertPEM(pemStr string) (*x509.Certificate, error) {
	block, rest := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("invalid cert PEM")
	}
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("unsupported cert PEM type: %s, only CERTIFICATE is supported", block.Type)
	}
	if len(rest) > 0 {
		if b, _ := pem.Decode(rest); b != nil {
			return nil, errors.New("only single certificate is supported")
		}
	}
	return x509.ParseCertificate(block.Bytes)
}

// parsePKCS8Key 解析 PKCS#8 私钥 PEM
// 只支持未加密的 PKCS#8
func parsePKCS8Key(pemStr string) (crypto.Signer, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("invalid key PEM")
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("unsupported key PEM type: %s, only PKCS#8 (PRIVATE KEY) is supported", block.Type)
	}
	if block.Headers["Proc-Type"] == "4,ENCRYPTED" {
		return nil, errors.New("encrypted PEM is not supported")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS#8: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("not a signer: %T", key)
	}
	return signer, nil
}

// matchCertAndKey 校验私钥和证书是否匹配
func matchCertAndKey(cert *x509.Certificate, signer crypto.Signer) error {
	certPubDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return err
	}
	keyPubDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return err
	}
	if !bytes.Equal(certPubDER, keyPubDER) {
		return errors.New("private key does not match certificate")
	}
	return nil
}
