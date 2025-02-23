package models

import "spki/src/database/mysql"

func InstallPrivateKey(data PrivateKey) error {
	err := mysql.OrmDB.Create(&data).Error
	return err
}
