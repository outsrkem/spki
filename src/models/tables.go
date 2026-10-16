package models

import (
	"errors"

	"spki/src/database/mysql"

	"gorm.io/gorm"
)

const (
	GenreRoot  = 1
	GenreInter = 2
	GenreLeaf  = 3
)

// ---------- 事务版：SaveCertBundle ----------

// SaveCertBundle 事务保存 certificate + private_key + version
// 若 creator 不存在则自动创建
func SaveCertBundle(cert Certificate, key *PrivateKey, version Version, account string) error {
	return mysql.OrmDB.Transaction(func(tx *gorm.DB) error {

		// certificate
		if err := tx.Create(&cert).Error; err != nil {
			return err
		}
		// private_key（CSR 模式为 nil）
		if key != nil {
			if err := tx.Create(key).Error; err != nil {
				return err
			}
		}
		// version
		if err := tx.Create(&version).Error; err != nil {
			return err
		}
		return nil
	})
}

// RevokeCertTx 事务吊销：只更新 version
func RevokeCertTx(certID string, state string, revocationTime int64) error {
	return mysql.OrmDB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&Version{}).
			Where("certid = ?", certID).
			Update("state", state).Error; err != nil {
			return err
		}
		if err := tx.Model(&Version{}).
			Where("certid = ?", certID).
			Update("revocation_time", revocationTime).Error; err != nil {
			return err
		}
		return nil
	})
}

// DeleteCertTx 事务删除
func DeleteCertTx(certID string) error {
	return mysql.OrmDB.Transaction(func(tx *gorm.DB) error {
		var versions []Version
		if err := tx.Where("certid = ?", certID).Find(&versions).Error; err != nil {
			return err
		}
		if err := tx.Where("certid = ?", certID).Delete(&Version{}).Error; err != nil {
			return err
		}
		if err := tx.Where("certid = ?", certID).Delete(&Certificate{}).Error; err != nil {
			return err
		}
		for _, v := range versions {
			if v.KeyID == nil {
				continue
			}
			var cnt int64
			if err := tx.Model(&Version{}).Where("keyid = ?", *v.KeyID).Count(&cnt).Error; err != nil {
				return err
			}
			if cnt == 0 {
				if err := tx.Where("keyid = ?", *v.KeyID).Delete(&PrivateKey{}).Error; err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// ListRevokedByIssuer 查出某 CA 下所有已吊销的末端证书版本
func ListRevokedByIssuer(issuerID string) ([]Version, error) {
	var list []Version
	err := mysql.OrmDB.
		Table("pki_version").
		Joins("JOIN pki_certificate ON pki_certificate.certid = pki_version.certid").
		Where("pki_certificate.parent_id = ? AND pki_version.state = ?", issuerID, "R").
		Find(&list).Error
	return list, err
}

// GetMaxRevision 取某证书当前最大版本号
func GetMaxRevision(certID string) (int, error) {
	var m int
	err := mysql.OrmDB.Model(&Version{}).
		Where("certid = ?", certID).
		Select("COALESCE(MAX(revision), 0)").
		Scan(&m).Error
	return m, err
}

// SaveVersionWithKey 事务：写 private_key（可选）+ version
// 续期时若复用旧私钥，key 传 nil
func SaveVersionWithKey(key *PrivateKey, version Version) error {
	return mysql.OrmDB.Transaction(func(tx *gorm.DB) error {
		if key != nil {
			if err := tx.Create(key).Error; err != nil {
				return err
			}
		}
		if err := tx.Create(&version).Error; err != nil {
			return err
		}
		return nil
	})
}

// ListCertificatesByGenre 按类型列出证书
// genre = -1 时返回全部
func ListCertificatesByGenre(genre int, userID string) ([]Certificate, error) {
	var list []Certificate
	q := mysql.OrmDB.Model(&Certificate{})
	if genre > 0 {
		q = q.Where("genre = ?", genre)
	}
	if userID != "" {
		q = q.Where("user_id = ?", userID)
	}
	err := q.Order("kid desc").Find(&list).Error
	return list, err
}

// ListCertificatesByGenres 按多个类型列出证书
// hasKey: -1 不过滤；0 只查无私钥；1 只查有私钥
func ListCertificatesByGenres(offset, limit int, count *int64, genres []int, hasKey int, userID string) ([]Certificate, error) {
	var list []Certificate
	q := mysql.OrmDB.Model(&Certificate{})

	if len(genres) > 0 {
		q = q.Where("genre IN ?", genres)
	}
	if hasKey >= 0 {
		q = q.Where("has_key = ?", hasKey)
	}
	if userID != "" {
		q = q.Where("user_id = ?", userID)
	}

	err := q.Count(count).Order("kid DESC").Offset(offset).Limit(limit).Find(&list).Error
	return list, err
}

// FindCASubject 按 Subject 查 CA（只查根 CA 和中间 CA）
func FindCASubject(subject string) (*Certificate, error) {
	var c Certificate
	err := mysql.OrmDB.
		Where("subject = ? AND genre IN (?, ?)", subject, 1, 2).
		First(&c).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &c, err
}

// GetVersionByFingerprint 按证书指纹查版本
func GetVersionByFingerprint(fp string) (*Version, error) {
	var v Version
	err := mysql.OrmDB.Where("fingerprint = ?", fp).First(&v).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &v, err
}

// GetPrivateKeyByFingerprint 按公钥指纹查私钥
func GetPrivateKeyByFingerprint(fp string) (*PrivateKey, error) {
	var k PrivateKey
	err := mysql.OrmDB.Where("fingerprint = ?", fp).First(&k).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &k, err
}
