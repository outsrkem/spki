package answer

const (
	EcodeOK                        = "SPKI.0000" // 结果正常
	EcodeError                     = "SPKI.0101" // 结果错误
	EcodeInvalidRequestParamsError = "SPKI.0102" // 请求参数校验失败。
	EcodeInvalidRequestError       = "SPKI.0103" // 请求体错误
	EcodeInvalidTokenError         = "SPKI.0175" // 无效，错误的 token
	EcodeNoActionError             = "SPKI.0177" // action 不存在
	EcodePolicyNotAuthorized       = "SPKI.0178" // 策略未授权此操作
	EcodeDeleteResourceConflict    = "SPKI.0198" // 409 删除资源时冲突
)
