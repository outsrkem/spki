package models

type Creator struct {
	ID     *int    `gorm:"primaryKey;autoIncrement;column:id"`               // 主键，自增
	UserID *string `gorm:"type:char(32);default:null;column:user_id;unique"` // 用户 ID，唯一
	Name   *string `gorm:"type:varchar(255);default:null;column:name"`       // 用户名称
}

// TableName 设置表名
func (Creator) TableName() string {
	return "creator"
}

type Certificate struct {
	ID       *int    `gorm:"primaryKey;autoIncrement;column:id"`              // 主键，自增
	CertID   *string `gorm:"type:char(32);default:null;column:certid;unique"` // 证书 ID，唯一
	UserID   *string `gorm:"type:char(32);not null;column:user_id"`           // 用户 ID，外键
	Title    *string `gorm:"type:varchar(255);default:null;column:title"`     // 证书友好名称
	State    *string `gorm:"type:varchar(255);default:null;column:state"`     // 状态
	Subject  *string `gorm:"type:varchar(255);default:null;column:subject"`   // 证书 Subject
	ParentID *string `gorm:"type:char(36);default:null;column:parent_id"`     // 上级证书 UUID
	Pathlev  *int    `gorm:"type:int;not null;column:pathlev"`                // 证书层级
	Genre    *int    `gorm:"type:int;not null;column:genre"`                  // 证书类型
	CertReq  *string `gorm:"type:varchar(255);default:null;column:cert_req"`  // 证书请求文件
}

// TableName 设置表名
func (Certificate) TableName() string {
	return "certificate"
}

type PrivateKey struct {
	ID         int    `gorm:"primaryKey;autoIncrement;column:id"`             // 主键，自增
	KeyID      string `gorm:"type:char(32);default:null;column:keyid;unique"` // 私钥 ID，唯一
	PrivateKey string `gorm:"type:text;not null;column:private_key"`          // 私钥内容
	CreateTime int64  `gorm:"type:bigint;default:null;column:create_time"`    // 创建时间戳
}

// TableName 设置表名
func (PrivateKey) TableName() string {
	return "private_key"
}

type Version struct {
	ID             int    `gorm:"primaryKey;autoIncrement;column:id"`              // 主键，自增
	CertID         string `gorm:"type:char(32);default:null;column:certid"`        // 证书 ID，外键
	KeyID          string `gorm:"type:char(32);default:null;column:keyid"`         // 私钥 ID，外键
	Serial         string `gorm:"type:varchar(255);default:null;column:serial"`    // 证书序列号
	Cert           string `gorm:"type:text;default:null;column:cert"`              // 证书文件主体
	EffectiveTime  int64  `gorm:"type:bigint;default:null;column:effective_time"`  // 生效时间戳
	ExpirationTime int64  `gorm:"type:bigint;default:null;column:expiration_time"` // 到期时间戳
	RevocationTime int64  `gorm:"type:bigint;default:null;column:revocation_time"` // 吊销时间戳
	Alarm          int    `gorm:"type:int;default:0;column:alarm"`                 // 到期告警
}

// TableName 设置表名
func (Version) TableName() string {
	return "version"
}
