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
	RevocationCode *int8   `gorm:"column:revocation_code"`
	State          *string `gorm:"column:state"`
}

func (Version) TableName() string { return "pki_version" }

const (
	ReasonUnspecified          int8 = 0
	ReasonKeyCompromise        int8 = 1
	ReasonCACompromise         int8 = 2
	ReasonAffiliationChanged   int8 = 3
	ReasonSuperseded           int8 = 4
	ReasonCessationOfOperation int8 = 5
	ReasonCertificateHold      int8 = 6 // 若不支持 hold，可不开放
	ReasonRemoveFromCRL        int8 = 8 // 与 6 配对，若不支持可不开放
	ReasonPrivilegeWithdrawn   int8 = 9
	ReasonAACompromise         int8 = 10
)

// IsValidRevocationCode 校验原因码是否合法（7 号保留不用）
func IsValidRevocationCode(c int8) bool {
	switch c {
	case ReasonUnspecified, ReasonKeyCompromise, ReasonCACompromise,
		ReasonAffiliationChanged, ReasonSuperseded, ReasonCessationOfOperation,
		ReasonCertificateHold, ReasonRemoveFromCRL,
		ReasonPrivilegeWithdrawn, ReasonAACompromise:
		return true
	}
	return false
}

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

// GetCertificateBySerial 按序列号（hex 字符串）查证书记录
// 注意：同一 serial 理论上只对应一张证书，但版本表里可能有多个 revision
// 这里返回 certificate 主记录
func (d *DB) GetCertificateBySerial(serial string) (*Certificate, error) {
	var v Version
	err := d.db.Where("serial = ?", serial).Order("revision DESC").First(&v).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	if v.CertID == nil {
		return nil, nil
	}
	var cert Certificate
	err = d.db.Where("certid = ?", *v.CertID).First(&cert).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &cert, nil
}

const StateRevoked = "R"

// ListRevokedByIssuerBySerial 查某个 issuer 下、指定 serial 的吊销记录
// issuerID 必须是 certid（对应 pki_certificate.parent_id）
// 返回最新的 version 记录（含 RevocationTime），未吊销返回 nil, nil
func (d *DB) ListRevokedByIssuerBySerial(issuerID, serial string) (*Version, error) {
	// 先找 issuer 下的所有直接子证书
	var certIDs []string
	err := d.db.Model(&Certificate{}).
		Where("parent_id = ?", issuerID).
		Pluck("certid", &certIDs).Error
	if err != nil {
		return nil, err
	}
	if len(certIDs) == 0 {
		return nil, nil
	}

	var v Version
	err = d.db.Where("certid IN ? AND serial = ? AND state = ?", certIDs, serial, StateRevoked).
		Order("revision DESC").
		First(&v).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &v, nil
}
