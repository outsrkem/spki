package uuid4

import (
	"strings"

	uuid "github.com/satori/go.uuid"
)

// Uuid4Str 生成uuidv4
func Uuid4Str() string {
	u4 := uuid.NewV4().String()
	return strings.ReplaceAll(u4, "-", "")
}

func Uuid4StrPtr() *string {
	u4 := uuid.NewV4().String()
	_uuid := strings.ReplaceAll(u4, "-", "")
	return &_uuid
}
