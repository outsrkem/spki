package models

import "spki/src/database/mysql"

func InstallCertVersion(data Version) error {
	err := mysql.OrmDB.Create(&data).Error
	return err
}
