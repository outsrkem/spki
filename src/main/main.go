package main

import (
	"time"

	"spki/src/config"
	"spki/src/database/mysql"
	"spki/src/route"
	"spki/src/service/cacert"
	"spki/src/slog"

	"github.com/cloudwego/hertz/pkg/app/server"
	"github.com/cloudwego/hertz/pkg/common/hlog"
)

// NewCAConfig 创建一个默认的 CA 配置
// 返回 (nil, error) 而不是 panic，便于调用方处理
//func NewCAConfig() (*cacert.CAConfig, error) {
//	configJSON := `{
//		"key": {
//			"algo": "rsa",
//			"size": 2048
//		},
//		"names": {
//			"CN": "AAA PrivateSign Root CA",
//			"O":  "PrivateSign",
//			"OU": "PrivateSign"
//		},
//		"expiry": 8760,
//		"subjectKeyIdentifier": "sha256"
//	}`
//
//	var cfg cacert.CAConfig
//	if err := json.Unmarshal([]byte(configJSON), &cfg); err != nil {
//		return nil, fmt.Errorf("failed to parse CA config: %w", err)
//	}
//	return &cfg, nil
//}

// init 在包初始化时执行，加载全局配置
func init() {
	config.Initializer()
}

func main() {
	// 1. 加载默认 CA 配置（仅示例，真实 CA 由 HTTP 接口 /ca/init 创建）
	//defaultCfg, err := NewCAConfig()
	//if err != nil {
	//	log.Fatalf("load default CA config failed: %v", err)
	//}
	//fmt.Printf("default CA config: %+v\n", defaultCfg)

	// 2. 示例：生成一把 CA 私钥并输出 PKCS#8 PEM
	//    生产环境下由 cacert.InitCa() 的 HTTP handler 按请求生成
	//caPrivateKey, err := genkey.CreateKey(defaultCfg.Key.Algo, defaultCfg.Key.Size)
	//if err != nil {
	//	log.Fatalf("CreateKey failed: %v", err)
	//}
	//pemBytes, err := genkey.PrivateKeyToPEM(caPrivateKey)
	//if err != nil {
	//	log.Fatalf("PrivateKeyToPEM failed: %v", err)
	//}
	//fmt.Printf("generated CA private key (PKCS#8 PEM):\n%s\n", pemBytes)

	// 3. 初始化全局配置 / 日志 / 数据库
	appCfg := config.InitConfig()
	slog.InitLog(appCfg.Spki.Log.Level)
	mysql.InitDB(&appCfg.Spki.Database)
	hlog.Info("start server")
	cacert.InitVectorKey(appCfg.Spki.Vector.K0)

	// 4. 启动 Hertz 服务器
	h := server.Default(
		server.WithHostPorts(appCfg.Spki.App.Bind),
		server.WithExitWaitTime(0*time.Second),
	)
	route.Routes(h)
	h.Spin()
}
