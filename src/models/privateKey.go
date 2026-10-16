package models

import (
	"errors"
	"gorm.io/gorm"
	"spki/src/database/mysql"
)

type PrivateKey struct {
	ID          int     `gorm:"column:kid;primaryKey;autoIncrement"`
	InstanceID  string  `gorm:"column:instance_id"`
	KeyID       string  `gorm:"column:keyid"`
	PrivateKey  string  `gorm:"column:private_key"`
	Passphrase  string  `gorm:"column:passphrase"` // 加密后的口令
	Fingerprint *string `gorm:"column:fingerprint"`
	CreateTime  int64   `gorm:"column:create_time"`
}

func (PrivateKey) TableName() string { return "pki_private_key" }

func GetPrivateKeyByKeyID(keyID string) (*PrivateKey, error) {
	var k PrivateKey
	err := mysql.OrmDB.Where("keyid = ?", keyID).First(&k).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &k, err
}
