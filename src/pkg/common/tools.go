package common

import (
	"encoding/json"
	"spki/src/pkg/crypto"
	"spki/src/pkg/uuid4"
	"strconv"
	"time"

	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/common/hlog"
)

const chars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

// CreateTimestamp 创建时间戳
func CreateTimestamp() int64 {
	t := time.Now().UnixNano() / 1e6
	return t
}

// CreateUuid 创建uuid
func CreateUuid() string {
	return uuid4.Uuid4Str()
}

// Decryption 解密密文
func Decryption(cipherText string) string {
	if cipherText == "" {
		return ""
	}
	plain, err := crypto.Decryption(cipherText)
	if err != nil {
		return ""
	}
	return plain
}

// Encryption 加密明文
func Encryption(plain string) string {
	if plain == "" {
		return ""
	}
	cipher := crypto.Encryption(plain)
	return cipher
}

func Str2Int(str string) (int, error) {
	n, err := strconv.Atoi(str)
	if err != nil {
		// Log the error if conversion fails.
		hlog.Errorf("string is: %s, err: %s", str, err)
		return 0, err
	}
	return n, nil
}

func GetRemoteIp(c *app.RequestContext) string {
	remoteIp := c.Request.Header.Get("X-Real-IP")
	if remoteIp == "" {
		remoteIp = c.ClientIP()
	}
	return remoteIp
}

func GetReqData(data interface{}) string {
	dataStr, err := json.Marshal(data)
	if err != nil {
		hlog.Error("json.Marshal: ", err)
	}
	return string(dataStr)
}
