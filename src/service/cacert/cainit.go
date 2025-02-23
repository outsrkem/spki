package cacert

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"spki/src/genkey"
	"spki/src/models"
	"spki/src/pkg/answer"
	"spki/src/pkg/common"
	"spki/src/pkg/uuid4"
	"strings"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/hlog"
)

type CAConfig struct {
	Title *string `json:"title"`
	Key   struct {
		Algo string `json:"algo"` // 私钥算法（如 "rsa"、"ecdsa"、"ed25519"）
		Size int    `json:"size"` // 密钥长度（RSA：2048、4096；ECDSA：256、384、521）
	} `json:"key"`
	Names struct {
		CN string  `json:"CN"`           // 通用名称（必填）
		C  *string `json:"C,omitempty"`  // 国家（可选）
		L  *string `json:"L,omitempty"`  // 城市（可选）
		ST *string `json:"ST,omitempty"` // 州/省（可选）
		O  string  `json:"O"`            // 组织（必填）
		OU string  `json:"OU"`           // 组织单位（必填）
	} `json:"names"`
	Expiry               int    `json:"expiry"`               // 有效期,单位是天
	SubjectKeyIdentifier string `json:"subjectKeyIdentifier"` // 生成 SubjectKeyId 的哈希算法:hash,sha256
}

// getPublicKey 从私钥中提取公钥
func getPublicKey(privateKey any) any {
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		return &key.PublicKey
	case *ecdsa.PrivateKey:
		return &key.PublicKey
	case ed25519.PrivateKey:
		return key.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}

// generateSubjectKeyId 根据指定的哈希算法生成 SubjectKeyId
func generateSubjectKeyId(pubKeyBytes []byte, algorithm string) ([]byte, error) {
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

// signca 自签名ca
func signca(privateKey any, cacfg *CAConfig) ([]byte, error) {
	var (
		pubKeyBytes []byte
		err         error
	)

	// 解析私钥类型
	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		pubKeyBytes, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
	case *ecdsa.PrivateKey:
		pubKeyBytes, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
	case ed25519.PrivateKey:
		pubKeyBytes, err = x509.MarshalPKIXPublicKey(key.Public().(ed25519.PublicKey))
	default:
		return nil, fmt.Errorf("unsupported private key type")
	}
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %v", err)
	}

	subjectKeyId, err := generateSubjectKeyId(pubKeyBytes, cacfg.SubjectKeyIdentifier)
	if err != nil {
		return nil, fmt.Errorf("failed to generate SubjectKeyId: %v", err)
	}
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128-1))
	if err != nil {
		panic(err)
	}
	subject := pkix.Name{
		CommonName:         cacfg.Names.CN,
		Organization:       []string{cacfg.Names.O},
		OrganizationalUnit: []string{cacfg.Names.OU},
	}
	if cacfg.Names.C != nil {
		// 将 *string 转换为 []string
		subject.Country = []string{*cacfg.Names.C}
	}
	if cacfg.Names.L != nil {
		subject.Locality = []string{*cacfg.Names.L}
	}
	if cacfg.Names.ST != nil {
		subject.Province = []string{*cacfg.Names.ST}
	}

	// 证书模板
	caTemplate := x509.Certificate{
		SerialNumber:          serialNumber, // 序列号，通常递增
		Subject:               subject,
		NotBefore:             time.Now(),                                                   // 生效时间
		NotAfter:              time.Now().Add(time.Duration(cacfg.Expiry) * 24 * time.Hour), // 过期时间
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,                 // 密钥用途
		IsCA:                  true,                                                         // 表示这是一个CA证书
		BasicConstraintsValid: true,                                                         // 表示这是一个CA证书
		AuthorityKeyId:        subjectKeyId,
		SubjectKeyId:          subjectKeyId,
	}
	// 自签名
	ca, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, getPublicKey(privateKey), privateKey)
	if err != nil {
		panic(err)
	}

	return ca, nil
}

// byte2base64 把byte切片转化为base64
func byte2base64(data *[]byte) (string, error) {
	if data == nil {
		return "", fmt.Errorf("data is nil") // 如果指针为 nil，返回空字符串
	}
	return base64.StdEncoding.EncodeToString(*data), nil // 解引用并编码
}
func StringPtr(s string) *string {
	return &s
}

func IntPtr(i int) *int {
	return &i
}
func setSubject(cacfg CAConfig) *string {
	name := cacfg.Names
	// 使用 strings.Builder 提高字符串拼接效率
	var builder strings.Builder

	// 定义字段和对应的前缀
	fields := []struct {
		prefix string
		value  *string
	}{
		{"/C=", name.C},
		{"/L=", name.L},
		{"/ST=", name.ST},
	}

	// 遍历字段，拼接非空值
	for _, field := range fields {
		if field.value != nil {
			builder.WriteString(field.prefix)
			builder.WriteString(*field.value)
		}
	}

	// 拼接固定字段
	builder.WriteString("/O=")
	builder.WriteString(name.O)
	builder.WriteString("/OU=")
	builder.WriteString(name.OU)
	builder.WriteString("/CN=")
	builder.WriteString(name.CN)

	// 返回结果
	subject := builder.String()
	return &subject
}

// InitCa 创建ca证书
func InitCa() func(ctx context.Context, c *app.RequestContext) {
	return func(ctx context.Context, c *app.RequestContext) {
		var cacfg CAConfig
		if err := c.BindJSON(&cacfg); err != nil {
			hlog.Error("The request body is invalid. error: ", err)
			c.JSON(http.StatusBadRequest, answer.ResBody("444", "Invalid request data.", ""))
			return
		}

		cakey, _ := genkey.CreateKey(cacfg.Key.Algo, cacfg.Key.Size) // 创建私钥
		ca, err := signca(cakey, &cacfg)                             // ca 自签名
		if err != nil {
			c.JSON(http.StatusBadRequest, answer.ResBody("444", "签名失败.", ""))
			return
		}

		// 将私钥和ca保存在数据库
		userId := c.GetString("userId")
		account := c.GetString("account")

		creator, _ := models.FindByCreatorForIdFormDB(userId)
		if creator.UserID == nil {
			if err := models.InstallCreator(userId, account); err != nil {
				c.JSON(http.StatusBadRequest, answer.ResBody("444", "保存用户失败.", ""))
				return
			}
		}
		certID := uuid4.Uuid4StrPtr() // 证书id
		if err := models.CreateCertificate(models.Certificate{
			CertID:  certID,
			UserID:  &userId,
			Title:   cacfg.Title,
			State:   StringPtr("V"),
			Subject: setSubject(cacfg),
			Pathlev: IntPtr(0),
			Genre:   IntPtr(1),
		}); err != nil {
			return
		}
		keyId := uuid4.Uuid4Str() // 私钥id
		pemBytes, _ := genkey.PrivateKeyToPEM(cakey)
		if err != nil {
			fmt.Println("Failed to convert private key to PEM:", err)
			return
		}
		if err := models.InstallPrivateKey(models.PrivateKey{
			KeyID:      keyId,
			PrivateKey: string(pemBytes),
			CreateTime: common.CreateTimestamp(),
		}); err != nil {
			return
		}
		if err := models.InstallCertVersion(models.Version{
			CertID: *certID,
			KeyID:  keyId,
			Serial: "",
			Cert:   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca})),
		}); err != nil {
			return
		}
		c.JSON(http.StatusCreated, answer.ResBody("200", "", cacfg))
	}
}
