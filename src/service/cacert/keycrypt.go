package cacert

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/youmark/pkcs8"

	aescrypto "spki/src/pkg/crypto"
)

var vectorKey []byte

func InitVectorKey(keyB64 string) {
	if keyB64 == "" {
		panic("VECTOR_KEY is required")
	}
	k, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil || len(k) != 32 {
		panic("VECTOR_KEY must be 32-byte base64")
	}
	vectorKey = k
}

// encryptPrivateKey 用 PKCS#8 加密私钥，再用向量加密口令
// 返回：加密的私钥 PEM、加密的口令
func encryptPrivateKey(key any) (encKey string, encPassphrase string, err error) {
	// 1. 生成随机口令（32 字节）
	pwdBytes := make([]byte, 32)
	if _, err := rand.Read(pwdBytes); err != nil {
		return "", "", fmt.Errorf("gen passphrase: %w", err)
	}

	// 2. 用 PKCS#8 加密私钥（直接用原始字节）
	encDER, err := pkcs8.MarshalPrivateKey(key, pwdBytes, nil)
	if err != nil {
		return "", "", fmt.Errorf("marshal encrypted pkcs8: %w", err)
	}
	encKeyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "ENCRYPTED PRIVATE KEY",
		Bytes: encDER,
	}))

	// 3. 用向量加密口令
	encPassphrase, err = aescrypto.Encrypt(pwdBytes, vectorKey)
	if err != nil {
		return "", "", fmt.Errorf("encrypt passphrase: %w", err)
	}

	return encKeyPEM, encPassphrase, nil
}

// decryptPrivateKey 解口令，再解 PKCS#8 私钥
func decryptPrivateKey(encKeyPEM, encPassphrase string) (crypto.Signer, error) {
	// 1. 用向量解密口令（得到原始 32 字节）
	pwdBytes, err := aescrypto.Decrypt(encPassphrase, vectorKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt passphrase: %w", err)
	}

	// 2. 解析 PKCS#8 加密 PEM
	block, _ := pem.Decode([]byte(encKeyPEM))
	if block == nil {
		return nil, fmt.Errorf("invalid encrypted PEM")
	}
	if block.Type != "ENCRYPTED PRIVATE KEY" {
		return nil, fmt.Errorf("not an encrypted PKCS#8 key, got: %s", block.Type)
	}

	// 3. 用口令解密私钥
	key, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, pwdBytes)
	if err != nil {
		return nil, fmt.Errorf("parse pkcs8: %w", err)
	}

	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("not a signer: %T", key)
	}
	return signer, nil
}
