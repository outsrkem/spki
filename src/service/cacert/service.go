package cacert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
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
	encKey, encPassphrase, err := encryptPrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("encrypt private key: %w", err)
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
		PrivateKey: encKey,
		Passphrase: encPassphrase,
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
		PrivateKey: encKey,
		Passphrase: encPassphrase,
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
	issuerSigner, err := decryptPrivateKey(issuerKey.PrivateKey, issuerKey.Passphrase)
	if err != nil {
		return "", err
	}

	var key crypto.Signer
	var encKey string
	var encPassphrase string
	if cfg.CSRPem == "" {
		key, err = createKey(cfg.Key.Algo, cfg.Key.Size)
		if err != nil {
			return "", err
		}
		encKey, encPassphrase, err = encryptPrivateKey(key)
		if err != nil {
			return "", fmt.Errorf("encrypt private key: %w", err)
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
			PrivateKey: encKey,
			Passphrase: encPassphrase,
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

// ---------- 续签 ----------

// RenewCertSvc 续签统一入口
//   - 根 CA（parent_id == NULL）→ 自签名
//   - 中间 CA / 末端证书 → 上级 CA 签
func RenewCertSvc(certID string, expiry int) (int, error) {
	if expiry <= 0 {
		return 0, errors.New("expiry must be > 0")
	}

	cert, err := models.GetCertificateByCertID(certID)
	if err != nil {
		return 0, fmt.Errorf("get certificate: %w", err)
	}
	if cert == nil {
		return 0, errors.New("certificate not found")
	}

	// 根 CA：自签名
	if cert.ParentID == nil {
		return renewCert(certID, expiry, true, true)
	}

	// 中间 CA 或末端证书：上级签
	isCA := cert.Genre == GenreInter
	return renewCert(certID, expiry, isCA, false)
}

// renewCert 续签核心
//
//	selfSign = true  → 自签名（根 CA）
//	selfSign = false → 上级签（中间 CA / 末端证书）
//	isCA     = true  → CA 证书
//	isCA     = false → 末端证书
func renewCert(certID string, expiry int, isCA, selfSign bool) (int, error) {
	// 1. 查原证书
	cert, err := models.GetCertificateByCertID(certID)
	if err != nil || cert == nil {
		return 0, errors.New("certificate not found")
	}

	// 2. 查原证书最新版本
	oldVer, err := models.GetLatestVersion(certID)
	if err != nil || oldVer == nil {
		return 0, errors.New("version not found")
	}
	if oldVer.KeyID == nil {
		return 0, errors.New("old version has no key (CSR mode not supported)")
	}

	// 3. 复用旧私钥
	oldKey, err := models.GetPrivateKeyByKeyID(*oldVer.KeyID)
	if err != nil || oldKey == nil {
		return 0, errors.New("old private key not found")
	}
	signer, err := decryptPrivateKey(oldKey.PrivateKey, oldKey.Passphrase)
	if err != nil {
		return 0, fmt.Errorf("decrypt old key: %w", err)
	}

	// 4. 解析旧证书，还原配置
	oldCert, err := parseCertPEM(*oldVer.Cert)
	if err != nil {
		return 0, err
	}
	cfg := buildRenewConfig(cert, oldCert, expiry, isCA)

	// 5. 取签发者
	var parentCert *x509.Certificate
	var parentSigner crypto.Signer

	if !selfSign {
		issuer, err := models.GetCertificateByCertID(*cert.ParentID)
		if err != nil || issuer == nil {
			return 0, errors.New("issuer not found")
		}
		issuerVer, err := models.GetLatestVersion(*cert.ParentID)
		if err != nil || issuerVer == nil {
			return 0, errors.New("issuer version not found")
		}
		issuerKey, err := models.GetPrivateKeyByKeyID(*issuerVer.KeyID)
		if err != nil || issuerKey == nil {
			return 0, errors.New("issuer key not found")
		}
		parentCert, err = parseCertPEM(*issuerVer.Cert)
		if err != nil {
			return 0, err
		}
		parentSigner, err = decryptPrivateKey(issuerKey.PrivateKey, issuerKey.Passphrase)
		if err != nil {
			return 0, err
		}
	}

	// 6. 重新签一张
	der, err := signCert(signer, parentCert, parentSigner, cfg, isCA)
	if err != nil {
		return 0, fmt.Errorf("sign renew: %w", err)
	}
	newCert, err := x509.ParseCertificate(der)
	if err != nil {
		return 0, err
	}
	certPEM := pemEncode("CERTIFICATE", der)

	// 7. 取下一个 revision
	maxRev, err := models.GetMaxRevision(certID)
	if err != nil {
		return 0, err
	}
	rev := maxRev + 1

	// 8. 组装新 version
	serial := newCert.SerialNumber.Text(16)
	eff := newCert.NotBefore.UnixMilli()
	exp := newCert.NotAfter.UnixMilli()
	alarm := int8(0)

	newVer := models.Version{
		Revision:       &rev,
		CertID:         &certID,
		KeyID:          oldVer.KeyID,
		Serial:         &serial,
		Cert:           strPtr(string(certPEM)),
		EffectiveTime:  &eff,
		ExpirationTime: &exp,
		Alarm:          &alarm,
	}

	// 9. 事务写入
	if err := models.SaveVersionWithKey(nil, newVer); err != nil {
		return 0, err
	}
	return rev, nil
}

// buildRenewConfig 从旧证书还原续期配置
func buildRenewConfig(cert *models.Certificate, oldCert *x509.Certificate, expiry int, isCA bool) *CertConfig {
	cfg := &CertConfig{
		Title:                cert.Title,
		Expiry:               expiry,
		SubjectKeyIdentifier: "sha256",
		Names: Names{
			CN: oldCert.Subject.CommonName,
		},
	}

	// 关键：从旧证书推断算法和长度
	cfg.Key = inferKeySpec(oldCert)

	if len(oldCert.Subject.Organization) > 0 {
		cfg.Names.O = oldCert.Subject.Organization[0]
	}
	if len(oldCert.Subject.OrganizationalUnit) > 0 {
		cfg.Names.OU = oldCert.Subject.OrganizationalUnit[0]
	}
	if len(oldCert.Subject.Country) > 0 {
		cfg.Names.C = &oldCert.Subject.Country[0]
	}
	if len(oldCert.Subject.Locality) > 0 {
		cfg.Names.L = &oldCert.Subject.Locality[0]
	}
	if len(oldCert.Subject.Province) > 0 {
		cfg.Names.ST = &oldCert.Subject.Province[0]
	}

	cfg.KeyUsage = keyUsageToStrings(oldCert.KeyUsage)

	if !isCA {
		cfg.ExtKeyUsage = extKeyUsageToStrings(oldCert.ExtKeyUsage)
		cfg.DNSNames = oldCert.DNSNames
		cfg.EmailAddresses = oldCert.EmailAddresses
		for _, ip := range oldCert.IPAddresses {
			cfg.IPAddresses = append(cfg.IPAddresses, ip.String())
		}
	}

	if isCA && oldCert.MaxPathLen >= 0 {
		pl := oldCert.MaxPathLen
		cfg.PathLen = &pl
	}

	return cfg
}

// inferKeySpec 从旧证书的公钥推断算法和长度
func inferKeySpec(cert *x509.Certificate) KeySpec {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return KeySpec{Algo: "rsa", Size: pub.N.BitLen()}
	case *ecdsa.PublicKey:
		return KeySpec{Algo: "ecdsa", Size: pub.Curve.Params().BitSize}
	case ed25519.PublicKey:
		return KeySpec{Algo: "ed25519", Size: 0}
	default:
		return KeySpec{Algo: "ecdsa", Size: 256}
	}
}

// keyUsageToStrings x509.KeyUsage → []string
func keyUsageToStrings(ku x509.KeyUsage) []string {
	var out []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
		out = append(out, "digitalSignature")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		out = append(out, "keyEncipherment")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		out = append(out, "certSign")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		out = append(out, "crlSign")
	}
	return out
}

// extKeyUsageNames 扩展密钥用途 常量 → 字符串
var extKeyUsageNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageServerAuth:      "serverAuth",
	x509.ExtKeyUsageClientAuth:      "clientAuth",
	x509.ExtKeyUsageCodeSigning:     "codeSigning",
	x509.ExtKeyUsageEmailProtection: "emailProtection",
	x509.ExtKeyUsageTimeStamping:    "timeStamping",
	x509.ExtKeyUsageOCSPSigning:     "ocspSigning",
	x509.ExtKeyUsageIPSECEndSystem:  "ipsecEndSystem",
	x509.ExtKeyUsageIPSECTunnel:     "ipsecTunnel",
	x509.ExtKeyUsageIPSECUser:       "ipsecUser",
}

// extKeyUsageToStrings []x509.ExtKeyUsage → []string
func extKeyUsageToStrings(eku []x509.ExtKeyUsage) []string {
	var out []string
	for _, e := range eku {
		if name, ok := extKeyUsageNames[e]; ok {
			out = append(out, name)
		}
	}
	return out
}

// ---------- 查询 ----------

// CertListItem 列表项 DTO
type CertListItem struct {
	CertID    string  `json:"certId"`
	Title     *string `json:"title,omitempty"`
	Subject   *string `json:"subject,omitempty"`
	State     *string `json:"state,omitempty"`
	ParentID  *string `json:"parentId,omitempty"`
	Pathlev   int     `json:"pathlev"`
	Genre     int     `json:"genre"`
	Revision  *int    `json:"revision,omitempty"`
	Serial    *string `json:"serial,omitempty"`
	NotBefore *int64  `json:"notBefore,omitempty"`
	NotAfter  *int64  `json:"notAfter,omitempty"`
	Alarm     *int8   `json:"alarm,omitempty"`
}

// VersionItem 版本列表项 DTO
type VersionItem struct {
	Revision       *int    `json:"revision"`
	CertID         *string `json:"certId"`
	KeyID          *string `json:"keyId"`
	Serial         *string `json:"serial"`
	Cert           *string `json:"cert"`
	EffectiveTime  *int64  `json:"effectiveTime"`
	ExpirationTime *int64  `json:"expirationTime"`
	RevocationTime *int64  `json:"revocationTime,omitempty"`
	Alarm          *int8   `json:"alarm"`
}

// ListCertsByGenre 按类型列出证书，带最新版本信息
// genre = -1 时返回全部
func ListCertsByGenre(genre int, userID string) ([]CertListItem, error) {
	certs, err := models.ListCertificatesByGenre(genre, userID)
	if err != nil {
		return nil, err
	}

	items := make([]CertListItem, 0, len(certs))
	for _, c := range certs {
		item := CertListItem{
			CertID:   c.CertID,
			Title:    c.Title,
			Subject:  c.Subject,
			State:    c.State,
			ParentID: c.ParentID,
			Pathlev:  c.Pathlev,
			Genre:    c.Genre,
		}
		v, err := models.GetLatestVersion(c.CertID)
		if err == nil && v != nil {
			item.Revision = v.Revision
			item.Serial = v.Serial
			item.NotBefore = v.EffectiveTime
			item.NotAfter = v.ExpirationTime
			item.Alarm = v.Alarm
		}
		items = append(items, item)
	}
	return items, nil
}

// ListCertsByGenres 按多个类型列出证书
// genres 为空 → 全部
func ListCertsByGenres(genres []int, userID string) ([]CertListItem, error) {
	certs, err := models.ListCertificatesByGenres(genres, userID)
	if err != nil {
		return nil, err
	}

	items := make([]CertListItem, 0, len(certs))
	for _, c := range certs {
		item := CertListItem{
			CertID:   c.CertID,
			Title:    c.Title,
			Subject:  c.Subject,
			State:    c.State,
			ParentID: c.ParentID,
			Pathlev:  c.Pathlev,
			Genre:    c.Genre,
		}
		v, err := models.GetLatestVersion(c.CertID)
		if err == nil && v != nil {
			item.Revision = v.Revision
			item.Serial = v.Serial
			item.NotBefore = v.EffectiveTime
			item.NotAfter = v.ExpirationTime
			item.Alarm = v.Alarm
		}
		items = append(items, item)
	}
	return items, nil
}

// ListCertVersionsSvc 列出某证书的所有版本
func ListCertVersionsSvc(certID string) ([]VersionItem, error) {
	cert, err := models.GetCertificateByCertID(certID)
	if err != nil || cert == nil {
		return nil, errors.New("certificate not found")
	}

	versions, err := models.ListVersionsByCertID(certID)
	if err != nil {
		return nil, err
	}

	items := make([]VersionItem, 0, len(versions))
	for _, v := range versions {
		items = append(items, VersionItem{
			Revision:       v.Revision,
			CertID:         v.CertID,
			KeyID:          v.KeyID,
			Serial:         v.Serial,
			Cert:           v.Cert,
			EffectiveTime:  v.EffectiveTime,
			ExpirationTime: v.ExpirationTime,
			RevocationTime: v.RevocationTime,
			Alarm:          v.Alarm,
		})
	}
	return items, nil
}

// RootInfo 根 CA 信息
type RootInfo struct {
	CertID    string   `json:"certId"`
	Title     *string  `json:"title,omitempty"`
	Subject   *string  `json:"subject,omitempty"`
	State     *string  `json:"state,omitempty"`
	Genre     int      `json:"genre"`
	Pathlev   int      `json:"pathlev"`
	Serial    *string  `json:"serial,omitempty"`
	NotBefore *int64   `json:"notBefore,omitempty"`
	NotAfter  *int64   `json:"notAfter,omitempty"`
	Chain     []string `json:"chain"` // 从末端到根的 certId 列表
}

// FindRootCASvc 从任意证书向上找到根 CA
func FindRootCASvc(certID string) (*RootInfo, error) {
	cur, err := models.GetCertificateByCertID(certID)
	if err != nil || cur == nil {
		return nil, errors.New("certificate not found")
	}

	chain := make([]string, 0, 4)
	var root *models.Certificate

	for cur != nil {
		chain = append(chain, cur.CertID)
		if cur.ParentID == nil {
			root = cur
			break
		}
		cur, err = models.GetCertificateByCertID(*cur.ParentID)
		if err != nil || cur == nil {
			break
		}
	}

	if root == nil {
		return nil, errors.New("root CA not found")
	}

	info := &RootInfo{
		CertID:  root.CertID,
		Title:   root.Title,
		Subject: root.Subject,
		State:   root.State,
		Genre:   root.Genre,
		Pathlev: root.Pathlev,
		Chain:   chain,
	}

	// 取最新版本信息
	v, err := models.GetLatestVersion(root.CertID)
	if err == nil && v != nil {
		info.Serial = v.Serial
		info.NotBefore = v.EffectiveTime
		info.NotAfter = v.ExpirationTime
	}

	return info, nil
}

// BuildRootPEM 从任意证书向上找到根 CA，返回根 CA 的 PEM
func BuildRootPEM(certID string) (string, error) {
	cur, err := models.GetCertificateByCertID(certID)
	if err != nil || cur == nil {
		return "", errors.New("certificate not found")
	}

	// 向上遍历，直到 parent_id == nil
	for cur != nil {
		if cur.ParentID == nil {
			v, err := models.GetLatestVersion(cur.CertID)
			if err != nil || v == nil {
				return "", errors.New("root version not found")
			}
			return *v.Cert, nil
		}
		cur, err = models.GetCertificateByCertID(*cur.ParentID)
		if err != nil || cur == nil {
			break
		}
	}
	return "", errors.New("root CA not found")
}
