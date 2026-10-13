package genkey

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

// CreateKey 创建私钥，algo：rsa、ecdsa、ed25519
// size 含义：
//   - rsa：密钥长度，建议 >= 2048
//   - ecdsa：曲线位数，支持 256、384、521
//   - ed25519：忽略
func CreateKey(algo string, size int) (any, error) {
	switch algo {
	case "rsa":
		if size < 2048 {
			return nil, fmt.Errorf("RSA key size must be >= 2048, got %d", size)
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
			return nil, fmt.Errorf("unsupported ECDSA key size: %d (supported: 256, 384, 521)", size)
		}
		return ecdsa.GenerateKey(curve, rand.Reader)

	case "ed25519":
		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ed25519 key: %w", err)
		}
		return privKey, nil

	default:
		return nil, fmt.Errorf("unsupported key algorithm: %s", algo)
	}
}

// PrivateKeyToPEM 将私钥转换为 PKCS#8 PEM 格式
// 支持 *rsa.PrivateKey、*ecdsa.PrivateKey、ed25519.PrivateKey
func PrivateKeyToPEM(privateKey any) ([]byte, error) {
	if privateKey == nil {
		return nil, errors.New("private key is nil")
	}

	// 统一使用 PKCS#8
	derBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key to PKCS#8: %w", err)
	}

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derBytes,
	}
	return pem.EncodeToMemory(pemBlock), nil
}

// GenerateRandomPassword 生成一个随机的强密码，字符集为 URL 安全 Base64
func GenerateRandomPassword(length int) (string, error) {
	if length <= 0 {
		return "", fmt.Errorf("password length must be > 0, got %d", length)
	}

	// Base64 每字符 6 位，向上取整所需字节数
	byteLength := (length*6 + 7) / 8

	randomBytes := make([]byte, byteLength)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	password := base64.URLEncoding.EncodeToString(randomBytes)
	if len(password) < length {
		return "", errors.New("generated password shorter than requested")
	}
	return password[:length], nil
}
