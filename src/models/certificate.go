package models

import (
	"errors"
	"gorm.io/gorm"
	"spki/src/database/mysql"
)

type Certificate struct {
	ID         int     `gorm:"column:kid;primaryKey;autoIncrement"`
	InstanceID string  `gorm:"column:instance_id"`
	CertID     string  `gorm:"column:certid"`
	UserID     string  `gorm:"column:user_id"`
	Title      *string `gorm:"column:title"`
	Subject    *string `gorm:"column:subject"`
	ParentID   *string `gorm:"column:parent_id"`
	Pathlev    int     `gorm:"column:pathlev"`
	Genre      int     `gorm:"column:genre"`
	HasKey     int8    `gorm:"column:has_key"`
	CertReq    *string `gorm:"column:cert_req"`
}

func (Certificate) TableName() string { return "pki_certificate" }

func GetCertificateByCertID(certID string) (*Certificate, error) {
	var c Certificate
	err := mysql.OrmDB.Where("certid = ?", certID).First(&c).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &c, err
}

func (d *DB) GetCertificateByCertID(certID string) (*Certificate, error) {
	var c Certificate
	err := d.WithInstance().Where("certid = ?", certID).First(&c).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &c, err
}
