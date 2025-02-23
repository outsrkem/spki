package models

import (
	"spki/src/database/mysql"
)

func FindByCreatorForIdFormDB(UserId string) (*Creator, error) {
	var t Creator
	err := mysql.OrmDB.Model(&Creator{}).Where("user_id=?", UserId).Find(&t).Error
	return &t, err
}

func InstallCreator(UserId, Name string) error {
	data := Creator{UserID: &UserId, Name: &Name}
	err := mysql.OrmDB.Create(&data).Error
	return err
}
