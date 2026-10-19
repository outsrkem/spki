package models

import (
	"errors"

	"gorm.io/gorm"
)

const (
	GenreRoot  = 1
	GenreInter = 2
	GenreLeaf  = 3
)

// ---------- 事务版：SaveCertBundle ----------

func (d *DB) SaveCertBundle(cert Certificate, key *PrivateKey, version Version) error {
	cert.InstanceID = d.instanceId
	version.InstanceID = d.instanceId
	if key != nil {
		key.InstanceID = d.instanceId
	}
	return d.db.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&cert).Error; err != nil {
			return err
		}
		if key != nil {
			if err := tx.Create(key).Error; err != nil {
				return err
			}
		}
		return tx.Create(&version).Error
	})
}

// RevokeCertTx 事务吊销：只更新 version
func (d *DB) RevokeCertTx(certID string, state string, revocationTime int64, revocationCode int8) error {
	if !IsValidRevocationCode(revocationCode) {
		return errors.New("invalid revocation code")
	}
	return d.db.Transaction(func(tx *gorm.DB) error {
		return tx.Model(&Version{}).
			Where("instance_id = ? AND certid = ?", d.instanceId, certID).
			Updates(map[string]any{
				"state":           state,
				"revocation_time": revocationTime,
				"revocation_code": revocationCode,
			}).Error
	})
}

// DeleteCertTx 事务删除
func (d *DB) DeleteCertTx(certID string) error {
	return d.db.Transaction(func(tx *gorm.DB) error {
		var versions []Version
		if err := tx.Where("instance_id = ? AND certid = ?", d.instanceId, certID).
			Find(&versions).Error; err != nil {
			return err
		}
		if err := tx.Where("instance_id = ? AND certid = ?", d.instanceId, certID).
			Delete(&Version{}).Error; err != nil {
			return err
		}
		if err := tx.Where("instance_id = ? AND certid = ?", d.instanceId, certID).
			Delete(&Certificate{}).Error; err != nil {
			return err
		}
		for _, v := range versions {
			if v.KeyID == nil {
				continue
			}
			var cnt int64
			if err := tx.Model(&Version{}).
				Where("instance_id = ? AND keyid = ?", d.instanceId, *v.KeyID).
				Count(&cnt).Error; err != nil {
				return err
			}
			if cnt == 0 {
				if err := tx.Where("instance_id = ? AND keyid = ?", d.instanceId, *v.KeyID).
					Delete(&PrivateKey{}).Error; err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// ListRevokedByIssuer 查出某 CA 下所有已吊销的末端证书版本
func (d *DB) ListRevokedByIssuer(issuerID string) ([]Version, error) {
	var list []Version
	err := d.db.
		Table("pki_version").
		Joins("JOIN pki_certificate ON pki_certificate.certid = pki_version.certid").
		Where("pki_version.instance_id = ?", d.instanceId).
		Where("pki_certificate.instance_id = ?", d.instanceId).
		Where("pki_certificate.parent_id = ? AND pki_version.state = ?", issuerID, "R").
		Find(&list).Error
	return list, err
}

// GetMaxRevision 取某证书当前最大版本号
func (d *DB) GetMaxRevision(certID string) (int, error) {
	var m int
	err := d.WithInstance().
		Model(&Version{}).
		Where("certid = ?", certID).
		Select("COALESCE(MAX(revision), 0)").
		Scan(&m).Error
	return m, err
}

// SaveVersionWithKey 事务：写 private_key（可选）+ version
func (d *DB) SaveVersionWithKey(key *PrivateKey, version Version) error {
	version.InstanceID = d.instanceId
	if key != nil {
		key.InstanceID = d.instanceId
	}
	return d.db.Transaction(func(tx *gorm.DB) error {
		if key != nil {
			if err := tx.Create(key).Error; err != nil {
				return err
			}
		}
		return tx.Create(&version).Error
	})
}

// ListCertificatesByGenres 按多个类型列出证书
// hasKey: -1 不过滤；0 只查无私钥；1 只查有私钥
func (d *DB) ListCertificatesByGenres(offset, limit int, count *int64, genres []int, hasKey int) ([]Certificate, error) {
	var list []Certificate
	q := d.WithInstance().Model(&Certificate{})

	if len(genres) > 0 {
		q = q.Where("genre IN ?", genres)
	}
	if hasKey >= 0 {
		q = q.Where("has_key = ?", hasKey)
	}

	err := q.Count(count).Order("kid DESC").Offset(offset).Limit(limit).Find(&list).Error
	return list, err
}

// FindCASubject 按 Subject 查 CA（只查根 CA 和中间 CA）
func (d *DB) FindCASubject(subject string) (*Certificate, error) {
	var c Certificate
	err := d.WithInstance().
		Where("subject = ? AND genre IN (?, ?)", subject, 1, 2).
		First(&c).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &c, err
}

// GetVersionByFingerprint 按证书指纹查版本
func (d *DB) GetVersionByFingerprint(fp string) (*Version, error) {
	var v Version
	err := d.WithInstance().Where("fingerprint = ?", fp).First(&v).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &v, err
}

// GetPrivateKeyByFingerprint 按公钥指纹查私钥
func (d *DB) GetPrivateKeyByFingerprint(fp string) (*PrivateKey, error) {
	var k PrivateKey
	err := d.WithInstance().Where("fingerprint = ?", fp).First(&k).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &k, err
}
