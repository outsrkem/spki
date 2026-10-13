package models

import (
	"errors"

	"spki/src/database/mysql"

	"gorm.io/gorm"
)

// ---------- 结构体 ----------

type Certificate struct {
	ID       int     `gorm:"column:id;primaryKey;autoIncrement"`
	CertID   string  `gorm:"column:certid"`
	UserID   string  `gorm:"column:user_id"`
	Title    *string `gorm:"column:title"`
	State    *string `gorm:"column:state"`
	Subject  *string `gorm:"column:subject"`
	ParentID *string `gorm:"column:parent_id"`
	Pathlev  int     `gorm:"column:pathlev"`
	Genre    int     `gorm:"column:genre"`
	CertReq  *string `gorm:"column:cert_req"`
}

func (Certificate) TableName() string { return "certificate" }

type PrivateKey struct {
	ID         int    `gorm:"column:id;primaryKey;autoIncrement"`
	KeyID      string `gorm:"column:keyid"`
	PrivateKey string `gorm:"column:private_key"`
	Passphrase string `gorm:"column:passphrase"` // 加密后的口令
	CreateTime int64  `gorm:"column:create_time"`
}

func (PrivateKey) TableName() string { return "private_key" }

type Version struct {
	ID             int     `gorm:"column:id;primaryKey;autoIncrement"`
	Revision       *int    `gorm:"column:revision"`
	CertID         *string `gorm:"column:certid"`
	KeyID          *string `gorm:"column:keyid"`
	Serial         *string `gorm:"column:serial"`
	Cert           *string `gorm:"column:cert"`
	EffectiveTime  *int64  `gorm:"column:effective_time"`
	ExpirationTime *int64  `gorm:"column:expiration_time"`
	RevocationTime *int64  `gorm:"column:revocation_time"`
	Alarm          *int8   `gorm:"column:alarm"`
}

func (Version) TableName() string { return "version" }

type Creator struct {
	ID       int     `gorm:"column:id;primaryKey;autoIncrement"`
	UserID   string  `gorm:"column:user_id"`
	Name     *string `gorm:"column:name"`
	SyncTime *int64  `gorm:"column:sync_time"`
}

func (Creator) TableName() string { return "creator" }

// ---------- Certificate ----------

func CreateCertificate(data Certificate) error {
	return mysql.OrmDB.Create(&data).Error
}

func GetCertificateByCertID(certID string) (*Certificate, error) {
	var c Certificate
	err := mysql.OrmDB.Where("certid = ?", certID).First(&c).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &c, err
}

func UpdateCertificateState(certID, state string) error {
	return mysql.OrmDB.Model(&Certificate{}).
		Where("certid = ?", certID).
		Update("state", state).Error
}

func DeleteCertificate(certID string) error {
	return mysql.OrmDB.Where("certid = ?", certID).Delete(&Certificate{}).Error
}

// ---------- PrivateKey ----------

func InstallPrivateKey(data PrivateKey) error {
	return mysql.OrmDB.Create(&data).Error
}

func GetPrivateKeyByKeyID(keyID string) (*PrivateKey, error) {
	var k PrivateKey
	err := mysql.OrmDB.Where("keyid = ?", keyID).First(&k).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &k, err
}

func DeletePrivateKey(keyID string) error {
	return mysql.OrmDB.Where("keyid = ?", keyID).Delete(&PrivateKey{}).Error
}

func CountPrivateKeyUsage(keyID string) (int64, error) {
	var cnt int64
	err := mysql.OrmDB.Model(&Version{}).Where("keyid = ?", keyID).Count(&cnt).Error
	return cnt, err
}

// ---------- Version ----------

func InstallCertVersion(data Version) error {
	return mysql.OrmDB.Create(&data).Error
}

func GetLatestVersion(certID string) (*Version, error) {
	var v Version
	err := mysql.OrmDB.Where("certid = ?", certID).Order("revision desc").First(&v).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &v, err
}

func ListVersionsByCertID(certID string) ([]Version, error) {
	var list []Version
	err := mysql.OrmDB.Where("certid = ?", certID).Order("revision asc").Find(&list).Error
	return list, err
}

func UpdateVersionRevocation(certID string, revocationTime int64) error {
	return mysql.OrmDB.Model(&Version{}).
		Where("certid = ?", certID).
		Update("revocation_time", revocationTime).Error
}

func DeleteVersionsByCertID(certID string) error {
	return mysql.OrmDB.Where("certid = ?", certID).Delete(&Version{}).Error
}

// ---------- Creator ----------

func CountCreator(userID string) (int64, error) {
	var cnt int64
	err := mysql.OrmDB.Model(&Creator{}).Where("user_id = ?", userID).Count(&cnt).Error
	return cnt, err
}

func InstallCreator(data Creator) error {
	return mysql.OrmDB.Create(&data).Error
}

// ---------- 事务版：SaveCertBundle ----------

// SaveCertBundle 事务保存 certificate + private_key + version
// 若 creator 不存在则自动创建
func SaveCertBundle(cert Certificate, key *PrivateKey, version Version, account string) error {
	return mysql.OrmDB.Transaction(func(tx *gorm.DB) error {
		// creator
		var cnt int64
		if err := tx.Model(&Creator{}).Where("user_id = ?", cert.UserID).Count(&cnt).Error; err != nil {
			return err
		}
		if cnt == 0 {
			creator := Creator{
				UserID: cert.UserID,
				Name:   strPtrIf(account),
			}
			if err := tx.Create(&creator).Error; err != nil {
				return err
			}
		}
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

// RevokeCertTx 事务吊销
func RevokeCertTx(certID, state string, revocationTime int64) error {
	return mysql.OrmDB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&Certificate{}).
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
		Table("version").
		Joins("JOIN certificate ON certificate.certid = version.certid").
		Where("certificate.parent_id = ? AND version.revocation_time IS NOT NULL", issuerID).
		Find(&list).Error
	return list, err
}

// GetMaxRevision 取某证书当前最大版本号
func GetMaxRevision(certID string) (int, error) {
	var max int
	err := mysql.OrmDB.Model(&Version{}).
		Where("certid = ?", certID).
		Select("COALESCE(MAX(revision), 0)").
		Scan(&max).Error
	return max, err
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

// ListCertificatesByGenre 按类型查证书
// genre: 1=根CA, 2=中间CA, 3=末端证书
func ListCertificatesByGenre(genre int, userID string) ([]Certificate, error) {
	var list []Certificate
	q := mysql.OrmDB.Where("genre = ?", genre)
	if userID != "" {
		q = q.Where("user_id = ?", userID)
	}
	err := q.Order("id desc").Find(&list).Error
	return list, err
}

// ---------- 工具 ----------

func strPtrIf(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
