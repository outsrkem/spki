package main

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"spki/gencert"
	"spki/initca"
	"spki/src/config"
	"spki/src/database/mysql"
	"spki/src/genkey"
	"spki/src/route"
	"spki/src/slog"
	"time"

	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/hlog"
)

type JSONData struct {
	Key struct {
		Algo string `json:"algo"`
		Size int    `json:"size"`
	} `json:"key"`
	Ca struct {
		Expiry string `json:"expiry"`
	} `json:"ca"`
	Names []struct {
		Cn string `json:"CN"` // 通用名称
		C  string `json:"C"`  // 国家
		L  string `json:"L"`  // 城市
		St string `json:"ST"` // 州/省
		O  string `json:"O"`  // 组织
		Ou string `json:"OU"` // 组织单位
	} `json:"names"`
}

type CAConfig struct {
	Key struct {
		Algo string `json:"algo"`
		Size int    `json:"size"`
	} `json:"key"`
	Names struct {
		Cn string `json:"CN"` // 通用名称
		C  string `json:"C"`  // 国家
		L  string `json:"L"`  // 城市
		St string `json:"ST"` // 州/省
		O  string `json:"O"`  // 组织
		Ou string `json:"OU"` // 组织单位
	} `json:"names"`
	Expiry               int    `json:"expiry"`               // 有效期
	SubjectKeyIdentifier string `json:"subjectKeyIdentifier"` // 生成 SubjectKeyId 的哈希算法
}

/*
		{
	    "expiry": "87600h",
	    "key": {
	        "algo": "rsa",
	        "size": 2048
	    },
	    "names": [
	        {
	            "CN": "harbor.hub.com",
	            "C": "CN",
	            "L": "ZJ",
	            "ST": "HZ",
	            "O": "harbor",
	            "OU": "IT"
	        }
	    ],
	    "v3_ext ": {
	        "KeyUsage": [
	            "keyEncipherment",
	            "dataEncipherment"
	        ],
	        "extendedKeyUsage": [
	            "serverAuth",
	            "clientAuth"
	        ],
	        "subjectAltName": {
	            "dns": [
	                "harbor.hub.com"
	            ],
	            "ip": [
	                "127.0.0.1",
	                "10.10.10.21"
	            ]
	        }
	    }
	}
*/

// NewCAConfig 创建一个默认的 CA 配置
func NewCAConfig() *CAConfig {
	configJSON := `{
		"key": {
			"algo": "rsa",
			"size": 2048
		},
		"names":
			{
				"CN": "AAA PrivateSign Root CA",
				"O": "PrivateSign",
				"OU": "PrivateSign"
			}
		,
		"expiry": 8760,
		"subjectKeyIdentifier": "sha256"
	}`
	var config CAConfig
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		panic(fmt.Errorf("failed to parse config: %v", err))
	}
	return &config
}

// init is a special function in Go that is called automatically when the package is initialized.
func init() {
	config.Initializer()
}

// main main
func main() {
	aa := NewCAConfig()
	// 创建CA私钥
	caPrivateKey, _ := genkey.GenkeyMain("rsa", 2048)
	// 创建csr
	// gencsr.GencsrMain(caPrivateKey)
	fmt.Print("%+v", aa)
	initca.InitCA(caPrivateKey)
	ca := `-----BEGIN CERTIFICATE-----
MIID6TCCAtGgAwIBAgIQdKK54IEVfDfoNvL5j5JOwzANBgkqhkiG9w0BAQsFADB+
MRAwDgYDVQQGEwdDb3VudHJ5MQ4wDAYDVQQIEwVTdGF0ZTENMAsGA1UEBxMEQ2l0
eTEdMBsGA1UEChMURXhhbXBsZSBPcmdhbml6YXRpb24xFTATBgNVBAsTDEV4YW1w
bGUgVW5pdDEVMBMGA1UEAxMMVGVzdCBDQSBSb290MB4XDTI1MDIwMzEzMzk1NVoX
DTI2MDIwMzEzMzk1NVowfjEQMA4GA1UEBhMHQ291bnRyeTEOMAwGA1UECBMFU3Rh
dGUxDTALBgNVBAcTBENpdHkxHTAbBgNVBAoTFEV4YW1wbGUgT3JnYW5pemF0aW9u
MRUwEwYDVQQLEwxFeGFtcGxlIFVuaXQxFTATBgNVBAMTDFRlc3QgQ0EgUm9vdDCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKUXxDGwE1YA2Apoa7A8kZ//
BjJl1mSxoqdan325gj5zjpaKs+iJpYYtzD4JeMe+ZLnQj4lt4JJKpI86ZADwNg2b
vIqxDYCXTrFMH+dYkst0sqmFfx5gQJuqQF2UKIZomI1GOJTiJdXxi4MjjOfBamUp
WHvqaZPSUS4kNEajBqGz87EPhg22pn4ZrQehm+pKcZ89BhRVzpep5bGc7Myy0Zgs
2RMmOUjzoF1DhvAhj8IIVX5O+oxCoh85I3wQA/YJEnGyNk8Cb0WYcOG3fXN04mIN
cj7jqWY9VcA4jPQ9jP0xuo5X2paCKc7WIZR3sk9Jw4EhBbD8qyJSYIk3AjSGfNEC
AwEAAaNjMGEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0O
BBYEFM99RlNZDrFcgr8FBsdbfQlJ4j1HMB8GA1UdIwQYMBaAFM99RlNZDrFcgr8F
BsdbfQlJ4j1HMA0GCSqGSIb3DQEBCwUAA4IBAQBV8QPr7D9m0XQ7ZEkdLqQizUIw
mZZpGpS8DRA8WpOwYxU/C7/8BiPsAgnvJ4tyYTEG68RN2OysBYkRvjQFPvPMQqM5
EKdJWusLi7sDFswJQnLYeP2Vc4nqJ23uX5hUKY7rXUnaPlAG5NKG5nkzetKo8VQy
6o7rA25aqZwG6p0djiayh1poqH3t/lAFQnbSAgqoKbvWnaaC4Swc4FyO4VTfOiAW
+e07WoY9N8EMOoFaJA4XX0En/kV+USdBZmOKmPWtNrUxBSBwe9C5A7Fm2cNal4Iy
aoFXHH636uYxskG3iogAKnocGhVoRMbft9uJvUzFB4lh6KoR5+xjJ6vqWKMs
-----END CERTIFICATE-----`
	cakey := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEApRfEMbATVgDYCmhrsDyRn/8GMmXWZLGip1qffbmCPnOOloqz
6Imlhi3MPgl4x75kudCPiW3gkkqkjzpkAPA2DZu8irENgJdOsUwf51iSy3SyqYV/
HmBAm6pAXZQohmiYjUY4lOIl1fGLgyOM58FqZSlYe+ppk9JRLiQ0RqMGobPzsQ+G
DbamfhmtB6Gb6kpxnz0GFFXOl6nlsZzszLLRmCzZEyY5SPOgXUOG8CGPwghVfk76
jEKiHzkjfBAD9gkScbI2TwJvRZhw4bd9c3TiYg1yPuOpZj1VwDiM9D2M/TG6jlfa
loIpztYhlHeyT0nDgSEFsPyrIlJgiTcCNIZ80QIDAQABAoIBACo61hjPrWKGfLzM
0R8XnziKB4/EtP604aJlb/69AS/wZzzi5fpJm2mjNWd5DMgrT6CoVM8WqCdDqKxq
h0ImL+1zNNtVRtrp2VtI2bBX29TnWPw8BbRDcsNe3XASgfs/riYVHEwZPQxo6QL2
iQiPVSPjW5r272K8nb9ry2N2ODAMarK7TLclyXyh3yG9oILjQniOh6ekeSAYeUnU
RSMqgmY+FPR6LGh6dIUSqeoZ4GlQlJ3XGTE6W1V0UWbYpM29OJCzEgRB7PWWzQ8i
CxjxEYFckvSxxSx543vByJrDxmdaxhGLazgnGRu9QnYYGUpSGUNMicQiZvuQ6lTM
2Wft3HECgYEA14iHivOpz7W0rLmKURE8L27nIFdoJCaUQiL5w08TBsE6VLeJsOZO
/JbOJ2Vl1IiUMSiwxpg5ip+Xr58nEcLUAUwmoj79y60tOENwqzbpz0WhG2HVhrgo
Z9Vhr8P+E5T9/IfUn1wX7rmq/nnoe4fsw1k9JW6VTPZAq8F4WF1TwKcCgYEAxBbY
/Fjd2zR17MOqKctBHsNopZFAe6Ss68iU4mX9iADIMtVswIqb47yTUclYzJWc+iZn
q5xEB1B6zemVgv35DEqwfgWS4ibuBWaku7ZXPRll+1dk2F5SQfFbGpGb4BnvvCCC
6g4YHZjjkzOQgZGejKBB/TPdBxkyLGqLUd5qzccCgYEAoNoFvg+m9Zr4Ice+kE26
ivPLjfltgT1BfDI6ECadXncqnzryiZD39c5eQEyOOJVNc3qYoz3MA8ajH7A5Kioq
qmU4l/FG25B8pPa/ySeMSuH+ID9dadNaZFN9Of2dSuPwwVxltCC4w7LRCGXWuQpy
CkA5QAxNZEiLbyNOOzQ7YxUCgYBtQd29HTbggKaEObGCgAHUxkR0nC41tlezOJvc
Wb+eG/FwgYKK9bBOgDAFjg6wT1yb9PImqHcvLCSAvvnTdvdhZexZC3oAEHjnAX4g
KUUKgjBUjylddZCXtYdxklgr0cfGJsdK6nd9ZkbHKiAGUcDp0hFyp4csAVn3bZYb
E7am2QKBgQC5MunNFnXjg3EK3g37DR11m10+Yy7BNW35y6HMNHS2ZfQeIU9CnG/v
LE6ewgk6VkNIr3WvU+jmttM4TOELtDGq06vyz1tYpCHmi/vlKry8oS7s9HVHX7Ea
egWz3xdwB9SnzoKdJwBjo3n6JCcNuQmdfkPujv+8utJOfQcJXyrQ/A==
-----END RSA PRIVATE KEY-----
`
	cablock, _ := pem.Decode([]byte(ca))
	cert, err := x509.ParseCertificate(cablock.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse certificate: %v", err)
	}
	keyblock, _ := pem.Decode([]byte(cakey))

	if keyblock == nil || keyblock.Type != "RSA PRIVATE KEY" {
		// fmt.Println(keyblock.Type)
		fmt.Println("---Failed to decode PEM data as RSA private key.")
		return
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(keyblock.Bytes)
	if err != nil {
		fmt.Println("Failed to parse RSA private key:", err)
		return
	}
	// akiExt := cert.AuthorityKeyId
	skid := cert.SubjectKeyId
	// 打印AuthorityKeyIdentifier的值
	// fmt.Println(akiExt)
	fmt.Println(skid)
	// fmt.Println(privateKey.PublicKey)

	gencert.Gencert(cert, privateKey)
	// 计算公钥的SubjectKeyId
	hash := crypto.SHA256.New()
	pkixBytes, _ := x509.MarshalPKIXPublicKey(privateKey.PublicKey)
	hash.Write(pkixBytes)
	subjectKeyId := hash.Sum(nil)
	fmt.Println(subjectKeyId)

	// ------------
	cfg := config.InitConfig()
	app := cfg.Spki.App
	slog.InitLog(cfg.Spki.Log.Level)
	mysql.InitDB(&cfg.Spki.Database)
	hlog.Info("start server")
	// 自动建表
	//mysql.AutoMigrateDB()
	h := server.Default(server.WithHostPorts(app.Bind), server.WithExitWaitTime(0*time.Second))
	route.Routes(h)
	h.Spin()
}
