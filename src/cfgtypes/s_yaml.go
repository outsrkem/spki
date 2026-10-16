package cfgtypes

import (
	"os"
	"spki/src/pkg/crypto"

	"gopkg.in/yaml.v3"

	"github.com/cloudwego/hertz/pkg/common/hlog"
)

// Config yaml配置结构体
type Config struct {
	Spki *Spki `yaml:"spki"`
}

type Spki struct {
	App      App      `yaml:"app"`
	Vector   Vector   `yaml:"vector"`
	Database Database `yaml:"database"`
	Ats      Ats      `yaml:"ats"`
	Uias     Uias     `yaml:"uias"`
	Log      Log      `yaml:"log"`
}

type App struct {
	Bind string `yaml:"bind"`
}

type Vector struct {
	K0 string `yaml:"k0"`
}

type Database struct {
	Host   string `yaml:"host"`
	Port   string `yaml:"port"`
	Name   string `yaml:"name"`
	User   string `yaml:"user"`
	Passwd string `yaml:"passwd"`
}

type Ats struct {
	Endpoint string `yaml:"endpoint"`
}

type Uias struct {
	Endpoint string `yaml:"endpoint"`
}

type Log struct {
	Level  string `yaml:"level"`
	Output Output `yaml:"output"`
}

type Output struct {
	File   File   `yaml:"file"`
	Stdout string `yaml:"stdout"`
}

type File struct {
	Name       string `yaml:"name"`
	MaxSize    int    `yaml:"maxsize"`
	MaxBackups int    `yaml:"maxbackups"`
	MaxAge     int    `yaml:"maxage"`
	Compress   bool   `yaml:"compress"`
}

// unmarshal is a method used to parse configuration data in a byte slice and fill it into the Config struct.
func (c *Config) unmarshal(d []byte) {
	if err := yaml.Unmarshal(d, c); err != nil {
		hlog.Error("Failed to parse the configuration file: ", err)
		os.Exit(1)
	}
}

// decryptionDatabaseMysqlPwd is a method used to decrypt the database password.
func (c *Config) decryptionDatabaseMysqlPwd() {
	if c.Spki.Database.Passwd != "" {
		if plain, err := crypto.Decryption(c.Spki.Database.Passwd); err != nil {
			hlog.Fatal("Decryption of database password failed. uias.yaml:uias.database.passwd ", c.Spki.Database.Passwd)
			os.Exit(100)
		} else {
			c.Spki.Database.Passwd = plain
		}
	}
}
