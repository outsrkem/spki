package models

import (
	"errors"

	"gorm.io/gorm"
)

type Version struct {
	ID             int     `gorm:"column:kid;primaryKey;autoIncrement"`
	InstanceID     string  `gorm:"column:instance_id"`
	Revision       *int    `gorm:"column:revision"`
	CertID         *string `gorm:"column:certid"`
	KeyID          *string `gorm:"column:keyid"`
	Serial         *string `gorm:"column:serial"`
	Fingerprint    *string `gorm:"column:fingerprint"`
	Cert           *string `gorm:"column:cert"`
	EffectiveTime  *int64  `gorm:"column:effective_time"`
	ExpirationTime *int64  `gorm:"column:expiration_time"`
	RevocationTime *int64  `gorm:"column:revocation_time"`
	State          *string `gorm:"column:state"`
}

func (Version) TableName() string { return "pki_version" }

func (d *DB) GetLatestVersion(certID string) (*Version, error) {
	var v Version
	err := d.WithInstance().
		Where("certid = ?", certID).
		Order("revision desc").
		First(&v).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &v, err
}

func (d *DB) ListVersionsByCertID(certID string) ([]Version, error) {
	var list []Version
	err := d.WithInstance().
		Where("certid = ?", certID).
		Order("revision asc").
		Find(&list).Error
	return list, err
}
