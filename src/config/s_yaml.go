package config

import (
	"gopkg.in/yaml.v3"
	"os"
	"spki/src/pkg/crypto"

	"github.com/cloudwego/hertz/pkg/common/hlog"
)

// Config yaml配置结构体
type Config struct {
	Spki *Spki `yaml:"spki"`
}

type Spki struct {
	App      App      `yaml:"app"`
	Database Database `yaml:"database"`
	Ats      Ats      `yaml:"ats"`
	Uias     Uias     `yaml:"uias"`
	Log      Log      `yaml:"log"`
}

type App struct {
	Bind string `yaml:"bind"`
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
	Level string `yaml:"level"`
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
