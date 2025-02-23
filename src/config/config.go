package config

import (
	"flag"
	"os"
	"time"

	"github.com/cloudwego/hertz/pkg/common/hlog"
)

// FlagArgs represents the command-line arguments for the application.
type FlagArgs struct {
	CfgPath      string
	PrintVersion bool
	Plain        string // 接收命令行字符串，用于加密
}

// NewFlagArgs creates a new FlagArgs object and parses command line flags.
func NewFlagArgs() *FlagArgs {
	fa := &FlagArgs{}
	flag.StringVar(&fa.CfgPath, "c", "spki.yaml", "Configuration file path.")
	flag.BoolVar(&fa.PrintVersion, "version", false, "Print version information and quit.")
	flag.StringVar(&fa.Plain, "encrypt", "", "Encrypted string.")
	flag.Parse()
	return fa
}

// configPath is a global variable that stores a pointer to the configuration file path.
var configPath *string
var AppCfg *Config

// Initializer function is used to initialize the application's configuration.
func Initializer() {
	fa := NewFlagArgs()
	if fa.PrintVersion { // 显示版本
		versions, _ := newVersions(Version, GoVersion, GitCommit)
		versions.Print(versions)
	}
	if fa.Plain != "" { // 加密命令行字符串
		encryption(fa.Plain)
	}
	configPath = &fa.CfgPath
}

// InitConfig 初始化配置
func InitConfig() *Config {
	hlog.Info("Read configuration file: ", *configPath)

	configData, err := os.ReadFile(*configPath)
	if err != nil {
		hlog.Error("Failed to read the configuration file: ", err)
		os.Exit(1)
	}

	var cfg Config
	cfg.unmarshal(configData)        // 解析配置文件
	cfg.decryptionDatabaseMysqlPwd() // 解密数据库密码
	AppCfg = &cfg
	return &cfg
}

type pkiConfig struct {
	Hostname          string
	CertFile          string
	CSRFile           string
	CAFile            string
	CAKeyFile         string
	TLSCertFile       string
	TLSKeyFile        string
	MutualTLSCAFile   string
	MutualTLSCNRegex  string
	TLSRemoteCAs      string
	MutualTLSCertFile string
	MutualTLSKeyFile  string
	KeyFile           string
	IntermediatesFile string
	CABundleFile      string
	IntBundleFile     string
	Address           string
	Port              int
	MinTLSVersion     string
	Password          string
	ConfigFile        string
	// CFG               *config.Config
	Profile          string
	IsCA             bool
	RenewCA          bool
	IntDir           string
	Flavor           string
	Metadata         string
	Domain           string
	IP               string
	Remote           string
	Label            string
	AuthKey          string
	ResponderFile    string
	ResponderKeyFile string
	Status           string
	Reason           string
	RevokedAt        string
	Interval         time.Duration
	List             bool
	Family           string
	Timeout          time.Duration
	Scanner          string
	CSVFile          string
	NumWorkers       int
	MaxHosts         int
	Responses        string
	Path             string
	CRL              string
	Usage            string
	PGPPrivate       string
	PGPName          string
	Serial           string
	CNOverride       string
	AKI              string
	DBConfigFile     string
	CRLExpiration    time.Duration
	Disable          string
}
