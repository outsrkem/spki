package models

// Certificate 对应 certificate 表
//type Certificate struct {
//	ID       int     `gorm:"column:id;primaryKey;autoIncrement"`
//	CertID   string  `gorm:"column:certid;uniqueIndex:uk_certid"`
//	UserID   string  `gorm:"column:user_id"`
//	Title    *string `gorm:"column:title"`
//	State    *string `gorm:"column:state"`
//	Subject  *string `gorm:"column:subject"`
//	ParentID *string `gorm:"column:parent_id"`
//	Pathlev  int     `gorm:"column:pathlev"`
//	Genre    int     `gorm:"column:genre"`
//	CertReq  *string `gorm:"column:cert_req"`
//}
//
//func (Certificate) TableName() string { return "certificate" }
//func InstallCertVersion(data Version) error {
//	err := mysql.OrmDB.Create(&data).Error
//	return err
//}
