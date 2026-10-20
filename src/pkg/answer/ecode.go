package answer

const (
	// ---------- 成功 ----------
	EcodeOK = "SPKI.0000" // 结果正常

	// ---------- 通用错误（5xx 兜底） ----------
	EcodeError = "SPKI.0101" // 结果错误（未分类的通用错误）

	// ---------- 请求/参数类（400） ----------
	EcodeInvalidRequestParamsError = "SPKI.0102" // 请求参数校验失败（字段缺失/格式错/取值越界）
	EcodeInvalidRequestError       = "SPKI.0103" // 请求体错误（JSON 解析失败、CSR 解析失败、PEM 格式错）
	EcodeUnsupported               = "SPKI.0104" // 不支持的算法/曲线/类型/用途
	EcodeInvalidExpiry             = "SPKI.0105" // 有效期格式或取值非法
	EcodeInvalidCSR                = "SPKI.0106" // CSR 签名校验失败
	EcodeInvalidCertPEM            = "SPKI.0107" // 证书 PEM 解析失败或类型不符
	EcodeInvalidKeyPEM             = "SPKI.0108" // 私钥 PEM 解析失败或类型不符
	EcodeKeyCertMismatch           = "SPKI.0109" // 私钥与证书不匹配
	EcodeNonCACertificate          = "SPKI.0110" // 目标证书不是 CA（不能签发/不能当父）
	EcodeCACannotSign              = "SPKI.0111" // CA 无私钥或无法签发（如 CSR 导入模式）
	EcodeInvalidRevocationReason   = "SPKI.0112" // 吊销原因码非法

	// ---------- 权限/授权类（401/403） ----------
	EcodeInstance404          = "SPKI.0401" // 实例不存在（沿用现有，HTTP 401）
	EcodeInvalidTokenError    = "SPKI.0175" // 无效/错误的 token（401）
	EcodeNoActionError        = "SPKI.0177" // action 不存在（404/400）
	EcodePolicyNotAuthorized  = "SPKI.0178" // 策略未授权此操作（403）
	EcodeCACannotBeDownloaded = "SPKI.0179" // CA 私钥不允许下载（403）
	EcodeRootCANotFound       = "SPKI.0180" // 向上找不到根 CA（403/404）

	// ---------- 资源不存在类（404） ----------
	Ecode404            = "SPKI.0404" // 通用资源不存在
	EcodeCertificate404 = "SPKI.0405" // 证书不存在
	EcodeVersion404     = "SPKI.0406" // 证书版本不存在
	EcodePrivateKey404  = "SPKI.0407" // 私钥不存在
	EcodeIssuer404      = "SPKI.0408" // 签发者（父 CA）不存在
	EcodeParentCA404    = "SPKI.0409" // 父 CA 不存在（导入时按 subject 匹配失败）

	// ---------- 冲突类（409） ----------
	EcodeResourceExists         = "SPKI.0196" // 资源已存在（证书/私钥重复导入）
	EcodeResourceConflict       = "SPKI.0197" // 通用资源冲突（状态不允许当前操作）
	EcodeDeleteResourceConflict = "SPKI.0198" // 删除资源时冲突（有子证书/被引用）
	EcodeCertRevoked            = "SPKI.0199" // 证书已吊销（重复吊销/续签已吊销证书）
)
