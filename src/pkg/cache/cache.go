package cache

import (
	"sync"
	"time"
)

// 缓存配置常量
const (
	DefaultCleanupInterval = 5 * time.Minute // 默认清理间隔
)

// 全局单例实例
var (
	globalStringCache *StringCache
	once              sync.Once
)

// StringCache 键值均为string类型的缓存结构，支持自动清理过期数据
type StringCache struct {
	cache           *sync.Map
	cleanupInterval time.Duration
}

// cacheItem 表示一个缓存条目，包装字符串值和过期时间
type cacheItem struct {
	value    string
	expireAt time.Time
}

// InitGlobalStringCache 初始化全局缓存，支持自定义清理间隔
func InitGlobalStringCache(interval time.Duration) {
	once.Do(func() {
		globalStringCache = &StringCache{
			cache:           new(sync.Map),
			cleanupInterval: interval,
		}
		go globalStringCache.startCleanupTicker()
	})
}

// GetGlobalStringCache 获取全局缓存实例，使用默认清理间隔
func GetGlobalStringCache() *StringCache {
	once.Do(func() {
		globalStringCache = &StringCache{
			cache:           new(sync.Map),
			cleanupInterval: DefaultCleanupInterval,
		}
		go globalStringCache.startCleanupTicker()
	})
	return globalStringCache
}

// startCleanupTicker 启动过期清理定时器
func (c *StringCache) startCleanupTicker() {
	ticker := time.NewTicker(c.cleanupInterval)
	defer ticker.Stop()
	for range ticker.C {
		c.cleanupExpired()
	}
}

// Set 缓存键值对（键值均为string），expireSeconds为过期时间（秒）
func (c *StringCache) Set(key, value string, expireSeconds int64) {
	item := cacheItem{
		value:    value,
		expireAt: time.Now().Add(time.Duration(expireSeconds) * time.Second),
	}
	c.cache.Store(key, item)
}

// Get 根据字符串键获取缓存值，返回值、是否存在且未过期
func (c *StringCache) Get(key string) (string, bool) {
	val, ok := c.cache.Load(key)
	if !ok {
		return "", false
	}

	item, ok := val.(cacheItem)
	if !ok {
		c.cache.Delete(key)
		return "", false
	}

	if time.Now().After(item.expireAt) {
		c.cache.Delete(key)
		return "", false
	}

	return item.value, true
}

// Update 更新已存在的缓存值，并从当前时间重新计算过期时间
// 参数:
//
//	key: 缓存键
//	newValue: 新的缓存值
//	expireSeconds: 新的过期时间（秒），从更新时刻开始计算
//
// 返回:
//
//	bool: 缓存是否存在且更新成功
func (c *StringCache) Update(key, newValue string, expireSeconds int64) bool {
	// 检查缓存是否存在
	val, ok := c.cache.Load(key)
	if !ok {
		return false // 缓存不存在，无法更新
	}

	// 验证缓存项格式
	item, ok := val.(cacheItem)
	if !ok {
		c.cache.Delete(key) // 清理脏数据
		return false
	}

	// 检查是否已过期（过期数据不允许更新，需重新Set）
	if time.Now().After(item.expireAt) {
		c.cache.Delete(key)
		return false
	}

	// 从当前时间重新计算过期时间
	updatedItem := cacheItem{
		value:    newValue,
		expireAt: time.Now().Add(time.Duration(expireSeconds) * time.Second),
	}
	c.cache.Store(key, updatedItem)
	return true
}

// Delete 主动删除指定键的缓存
func (c *StringCache) Delete(key string) {
	c.cache.Delete(key)
}

// cleanupExpired 清理所有过期的缓存条目
func (c *StringCache) cleanupExpired() {
	c.cache.Range(func(key, value interface{}) bool {
		item, ok := value.(cacheItem)
		if !ok {
			c.cache.Delete(key)
			return true
		}

		if time.Now().After(item.expireAt) {
			c.cache.Delete(key)
		}
		return true
	})
}

// Clear 清空所有缓存
func (c *StringCache) Clear() {
	c.cache.Range(func(key, value interface{}) bool {
		c.cache.Delete(key)
		return true
	})
}

// Count 返回缓存中的条目数量（包括可能已过期的）
func (c *StringCache) Count() int {
	count := 0
	c.cache.Range(func(key, value interface{}) bool {
		count++
		return true
	})
	return count
}

// GetCleanupInterval 返回当前清理间隔时间
func (c *StringCache) GetCleanupInterval() time.Duration {
	return c.cleanupInterval
}
