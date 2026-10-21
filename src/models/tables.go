package models

import (
	"errors"
	"fmt"

	"gorm.io/gorm"
)

const (
	GenreRoot  = 1
	GenreInter = 2
	GenreLeaf  = 3
)

var ErrHasChildren = errors.New("certificate has sub-certificates")

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

// RevokeCertTx 事务吊销：只更新未吊销的 version
func (d *DB) RevokeCertTx(certID string, state string, revocationTime int64, revocationCode int8) error {
	if !IsValidRevocationCode(revocationCode) {
		return errors.New("invalid revocation code")
	}
	return d.db.Transaction(func(tx *gorm.DB) error {
		return tx.Model(&Version{}).
			Where("instance_id = ? AND certid = ?", d.instanceId, certID).
			Where("state IS NULL OR state != ?", StateRevoked).
			Updates(map[string]any{
				"state":           state,
				"revocation_time": revocationTime,
				"revocation_code": revocationCode,
			}).Error
	})
}

// DeleteCertTx 事务删除
// FIX: 删除前检查是否有子证书，有则拒绝删除，避免产生孤儿证书
func (d *DB) DeleteCertTx(certID string) error {
	return d.db.Transaction(func(tx *gorm.DB) error {
		// 1. 检查是否有子证书
		var childCnt int64
		if err := tx.Model(&Certificate{}).
			Where("instance_id = ? AND parent_id = ?", d.instanceId, certID).
			Count(&childCnt).Error; err != nil {
			return err
		}
		if childCnt > 0 {
			return fmt.Errorf("%w: %d sub-certificate(s) exist", ErrHasChildren, childCnt)
		}

		// 2. 查该 certID 的所有 version（用于后续清理 key）
		var versions []Version
		if err := tx.Where("instance_id = ? AND certid = ?", d.instanceId, certID).
			Find(&versions).Error; err != nil {
			return err
		}

		// 3. 删 version
		if err := tx.Where("instance_id = ? AND certid = ?", d.instanceId, certID).
			Delete(&Version{}).Error; err != nil {
			return err
		}

		// 4. 删 certificate
		if err := tx.Where("instance_id = ? AND certid = ?", d.instanceId, certID).
			Delete(&Certificate{}).Error; err != nil {
			return err
		}

		// 5. 清理不再被引用的 private_key
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

// ListRevokedByIssuer 查出某 CA 下所有已吊销的子证书版本
func (d *DB) ListRevokedByIssuer(issuerID string) ([]Version, error) {
	var certIDs []string
	err := d.WithInstance().
		Model(&Certificate{}).
		Where("parent_id = ?", issuerID).
		Pluck("certid", &certIDs).Error
	if err != nil {
		return nil, err
	}
	if len(certIDs) == 0 {
		return nil, nil
	}

	var list []Version
	err = d.WithInstance().
		Where("certid IN ? AND state = ?", certIDs, StateRevoked).
		Order("revocation_time ASC").
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
