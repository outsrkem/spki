package models

import "spki/src/database/mysql"

func CreateCertificate(data Certificate) error {
	err := mysql.OrmDB.Create(&data).Error
	return err
}
