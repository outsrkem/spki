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
	"fmt"
)

func GenkeyMain(algo string, size int) (*rsa.PrivateKey, error) {
	caPrivateKey, err := rsa.GenerateKey(rand.Reader, size)
	if err != nil {
		panic(err)
	}
	return caPrivateKey, nil

}

// PrivateKeyToPEM 将私钥转换为 PEM 格式
func PrivateKeyToPEM(privateKey any) ([]byte, error) {
	var pemBlock *pem.Block

	switch key := privateKey.(type) {
	case *rsa.PrivateKey:
		// 将 RSA 私钥转换为 DER 格式
		derBytes := x509.MarshalPKCS1PrivateKey(key)
		pemBlock = &pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: derBytes,
		}
	case *ecdsa.PrivateKey:
		// 将 ECDSA 私钥转换为 DER 格式
		derBytes, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ECDSA private key: %v", err)
		}
		pemBlock = &pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: derBytes,
		}
	case ed25519.PrivateKey:
		// 将 Ed25519 私钥转换为 DER 格式
		derBytes, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Ed25519 private key: %v", err)
		}
		pemBlock = &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: derBytes,
		}
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", privateKey)
	}

	// 将 DER 格式的私钥编码为 PEM 格式
	pemBytes := pem.EncodeToMemory(pemBlock)
	return pemBytes, nil
}

// CreateKey 创建私钥，algo：rsa，ecdsa，ed25519
func CreateKey(algo string, size int) (any, error) {
	switch algo {
	case "rsa":
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
			return nil, fmt.Errorf("unsupported ECDSA key size: %d", size)
		}
		return ecdsa.GenerateKey(curve, rand.Reader)
	case "ed25519":
		_, privKey, err := ed25519.GenerateKey(rand.Reader)
		return privKey, err
	default:
		return nil, fmt.Errorf("unsupported key algorithm: %s", algo)
	}
}

// GenerateRandomPassword 生成一个随机的强密码
func GenerateRandomPassword(length int) (string, error) {
	// 计算需要的字节数（每个字节可以表示 6 位 Base64 字符）
	byteLength := (length * 6) / 8
	if (length*6)%8 != 0 {
		byteLength++
	}

	// 生成随机字节
	randomBytes := make([]byte, byteLength)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %v", err)
	}

	// 将随机字节编码为 Base64 字符串
	password := base64.URLEncoding.EncodeToString(randomBytes)

	// 截取指定长度的密码
	return password[:length], nil
}

func Test() {
	// 生成随机密码
	password, err := GenerateRandomPassword(32)
	if err != nil {
		fmt.Println("Failed to generate password:", err)
		return
	}
	fmt.Print(password)
}
