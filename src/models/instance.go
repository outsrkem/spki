package models

import (
	"errors"
	"spki/src/database/mysql"
	"time"

	"gorm.io/gorm"
)

type Instance struct {
	Kid           int    `gorm:"column:kid;primaryKey;autoIncrement"`
	InstanceID    string `gorm:"column:instance_id;uniqueIndex"`
	DomainID      string `gorm:"column:domain_id"`
	CBCStatus     string `gorm:"column:cbc_status"`
	CBCExpireTime *int64 `gorm:"column:cbc_expire_time"`
	CBCSyncTime   *int64 `gorm:"column:cbc_sync_time"`
	CreateTime    int64  `gorm:"column:create_time"`
}

func (Instance) TableName() string { return "pki_instance" }

// ---------- Instance ----------

// CreateInstance 插入实例
func CreateInstance(data Instance) error {
	return mysql.OrmDB.Create(&data).Error
}

// GetInstance queries an instance by DomainId
func GetInstance(DomainId string) (Instance, error) {
	var instance Instance
	r := mysql.OrmDB.Model(&Instance{}).Where("domain_id = ?", DomainId).First(&instance)
	return instance, r.Error
}

// GetInstanceByID 按 instanceID 查实例
func GetInstanceByID(instanceID string) (*Instance, error) {
	var inst Instance
	err := mysql.OrmDB.Where("instance_id = ?", instanceID).First(&inst).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &inst, err
}

// ListInstances 列出实例
// domainID 为空时不过滤域
// cbcStatus 为空时不过滤状态
func ListInstances(domainID, cbcStatus string) ([]Instance, error) {
	var list []Instance
	q := mysql.OrmDB.Model(&Instance{})
	if domainID != "" {
		q = q.Where("domain_id = ?", domainID)
	}
	if cbcStatus != "" {
		q = q.Where("cbc_status = ?", cbcStatus)
	}
	err := q.Order("kid desc").Find(&list).Error
	return list, err
}

// UpdateInstanceCBC 更新 CBC 同步状态
func UpdateInstanceCBC(instanceID, cbcStatus string, expireTime *int64) error {
	return mysql.OrmDB.Model(&Instance{}).
		Where("instance_id = ?", instanceID).
		Updates(map[string]any{
			"cbc_status":      cbcStatus,
			"cbc_expire_time": expireTime,
			"cbc_sync_time":   time.Now().UnixMilli(),
		}).Error
}

// CountInstances 统计实例数量
func CountInstances(domainID string) (int64, error) {
	var cnt int64
	q := mysql.OrmDB.Model(&Instance{})
	if domainID != "" {
		q = q.Where("domain_id = ?", domainID)
	}
	err := q.Count(&cnt).Error
	return cnt, err
}

// IsInstanceUsable 判断实例是否可用
func IsInstanceUsable(inst *Instance) bool {
	if inst == nil {
		return false
	}
	switch inst.CBCStatus {
	case "normal":
		return true
	case "expired", "arrears", "suspended":
		return false
	case "unknown":
		return false
	default:
		return false
	}
}
