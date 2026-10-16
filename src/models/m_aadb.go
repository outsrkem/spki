package models

import (
	"errors"
	"spki/src/database/mysql"
	"spki/src/pkg/common"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type DB struct {
	db          *gorm.DB      // DB 实例
	Klog        *logrus.Entry // 日志对象
	instanceId  string        // 实例ID
	CurrentTime int64         // 当前时间
}

// NewDBModel 创建DB实例
func NewDBModel(instanceId string) (*DB, error) {
	if instanceId == "" {
		return nil, errors.New("instanceId can not be empty")
	}
	_t := &DB{
		instanceId:  instanceId,
		db:          mysql.OrmDB,
		CurrentTime: common.CreateTimestamp(),
	}
	return _t, nil
}

// SetKlog 设置日志对象(可选)
func (d *DB) SetKlog(klog *logrus.Entry) *DB {
	d.Klog = klog
	return d
}

// SetCurrentTime 设置当前时间(可选)
func (d *DB) SetCurrentTime(currentTime int64) *DB {
	d.CurrentTime = currentTime
	return d
}

// WithInstance 带按实例ID查询的DB对象
func (d *DB) WithInstance() *gorm.DB {
	return d.db.Where("instance_id = ?", d.instanceId)
}
