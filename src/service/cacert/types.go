package cacert

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

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

type AltNames struct {
	DNS   []string `json:"dns,omitempty"`
	IP    []string `json:"ip,omitempty"`
	Email []string `json:"email,omitempty"`
	URI   []string `json:"uri,omitempty"`
}

// CertConfig 通用证书配置（CA、中间 CA、末端证书共用）
type CertConfig struct {
	Title                 *string  `json:"title,omitempty"`
	IssuerID              string   `json:"issuerId,omitempty"`
	ParentID              string   `json:"parentId,omitempty"`
	Key                   KeySpec  `json:"key"`
	Names                 Names    `json:"names"`
	Expiry                Expiry   `json:"expiry"`
	SubjectKeyIdentifier  string   `json:"subjectKeyIdentifier"`
	KeyUsage              []string `json:"keyUsage,omitempty"`
	ExtKeyUsage           []string `json:"extKeyUsage,omitempty"`
	CRLDistributionPoints []string `json:"crlDistributionPoints,omitempty"`
	OCSPServer            []string `json:"ocspServer,omitempty"`
	IssuingCertificateURL []string `json:"issuingCertificateURL,omitempty"`
	AltNames              AltNames `json:"alt_names,omitempty"`
	PathLen               *int     `json:"pathLen,omitempty"`
	CSRPem                string   `json:"csrpem,omitempty"`
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

// Expiry 有效期，支持：
//   - 数字：365（天）
//   - "365"、"100d"（天）
//   - "1y"（自然年）
//   - "3m"（自然月）
type Expiry struct {
	Years  int
	Months int
	Days   int
}

// UnmarshalJSON 兼容数字和字符串
func (e *Expiry) UnmarshalJSON(data []byte) error {
	fmt.Printf("Expiry.UnmarshalJSON called: %s\n", string(data))
	// 数字
	var num int
	if err := json.Unmarshal(data, &num); err == nil {
		parsed, err := ParseExpiry(strconv.Itoa(num))
		if err != nil {
			return err
		}
		*e = parsed
		return nil
	}
	// 字符串
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("expiry must be number or string: %w", err)
	}
	parsed, err := ParseExpiry(s)
	if err != nil {
		return err
	}
	*e = parsed
	return nil
}

// MarshalJSON 输出成字符串，例如 "1y"、"3m"、"100d"
func (e Expiry) MarshalJSON() ([]byte, error) {
	return json.Marshal(e.String())
}

// String 输出成可读字符串
func (e Expiry) String() string {
	if e.Years > 0 {
		return fmt.Sprintf("%dy", e.Years)
	}
	if e.Months > 0 {
		return fmt.Sprintf("%dm", e.Months)
	}
	if e.Days > 0 {
		return fmt.Sprintf("%dd", e.Days)
	}
	return ""
}

// ParseExpiry 解析字符串为 Expiry
func ParseExpiry(s string) (Expiry, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	if s == "" {
		return Expiry{}, fmt.Errorf("expiry is empty")
	}

	// 纯数字 → 天
	if n, err := strconv.Atoi(s); err == nil {
		if n <= 0 {
			return Expiry{}, fmt.Errorf("expiry must be > 0, got %d", n)
		}
		return Expiry{Days: n}, nil
	}

	// 带单位
	if len(s) < 2 {
		return Expiry{}, fmt.Errorf("invalid expiry: %s", s)
	}
	unit := s[len(s)-1]
	numStr := s[:len(s)-1]
	n, err := strconv.Atoi(numStr)
	if err != nil {
		return Expiry{}, fmt.Errorf("invalid expiry: %s", s)
	}
	if n <= 0 {
		return Expiry{}, fmt.Errorf("expiry must be > 0, got %d", n)
	}

	switch unit {
	case 'y':
		return Expiry{Years: n}, nil
	case 'm':
		return Expiry{Months: n}, nil
	case 'd':
		return Expiry{Days: n}, nil
	default:
		return Expiry{}, fmt.Errorf("unsupported expiry unit: %c (supported: y, m, d)", unit)
	}
}

// NotAfter 根据起始时间计算到期时间
func (e Expiry) NotAfter(from time.Time) time.Time {
	return from.AddDate(e.Years, e.Months, e.Days)
}
