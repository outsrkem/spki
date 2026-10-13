package cacert

// KeySpec 私钥配置
type KeySpec struct {
	Algo string `json:"algo"`
	Size int    `json:"size"`
}

// Names 主体信息
type Names struct {
	CN string  `json:"CN"`
	C  *string `json:"C,omitempty"`
	L  *string `json:"L,omitempty"`
	ST *string `json:"ST,omitempty"`
	O  string  `json:"O"`
	OU string  `json:"OU"`
}

// CertConfig 通用证书配置（CA、中间 CA、末端证书共用）
type CertConfig struct {
	Title                *string  `json:"title,omitempty"`
	IssuerID             string   `json:"issuerId,omitempty"`
	ParentID             string   `json:"parentId,omitempty"`
	Key                  KeySpec  `json:"key"`
	Names                Names    `json:"names"`
	Expiry               int      `json:"expiry"`
	SubjectKeyIdentifier string   `json:"subjectKeyIdentifier"`
	KeyUsage             []string `json:"keyUsage,omitempty"`
	ExtKeyUsage          []string `json:"extKeyUsage,omitempty"`
	DNSNames             []string `json:"dnsNames,omitempty"`
	IPAddresses          []string `json:"ipAddresses,omitempty"`
	EmailAddresses       []string `json:"emailAddresses,omitempty"`
	PathLen              *int     `json:"pathLen,omitempty"`
	CSRPem               string   `json:"csrpem,omitempty"`
}

// 状态常量
const (
	StateValid   = "V"
	StateRevoked = "R"
	StateExpired = "E"
)

// 路径层级常量
const (
	PathLevCA    = 0
	PathLevInter = 1
	PathLevLeaf  = 2
)

// 类型常量
const (
	GenreRoot  = 1
	GenreInter = 2
	GenreLeaf  = 3
)
