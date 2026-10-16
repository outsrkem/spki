package core

import (
	"errors"
	"spki/src/models"
	"spki/src/pkg/cache"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

// InstanceCacheKeyName 实例缓存KEY
func InstanceCacheKeyName(domainId string) string {
	return "instance:domain/" + domainId
}

const (
	Validity = 3600 * 2 // 实例ID缓存有效期(秒)
)

func GetInstanceId(klog *logrus.Entry, domainId string) (string, error) {
	if domainId == "" {
		return "", errors.New("user id is empty")
	}

	gCache := cache.GetGlobalStringCache()
	key := InstanceCacheKeyName(domainId)
	if instanceId, ok := gCache.Get(key); ok {
		klog.Debugf("get cache instance id %s", instanceId)
		return instanceId, nil
	}

	klog.Infof("Cache miss occurred. Query the database to obtain the instance. domainId: [%s]", domainId)
	instance, err := models.GetInstance(domainId)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
		}
		return "", err
	}
	instanceId := instance.InstanceID
	gCache.Set(key, instanceId, Validity)
	return instanceId, nil
}
