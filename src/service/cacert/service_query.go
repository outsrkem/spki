package cacert

import (
	"errors"
	"spki/src/models"
)

// CertListItem 列表项 DTO
type CertListItem struct {
	CertID    string   `json:"certId"`
	Title     *string  `json:"title,omitempty"`
	Subject   *string  `json:"subject,omitempty"`
	State     *string  `json:"state,omitempty"`
	ParentID  *string  `json:"parentId,omitempty"`
	Pathlev   int      `json:"pathlev"`
	Genre     int      `json:"genre"`
	HasKey    int8     `json:"hasKey"`
	Revision  *int     `json:"revision,omitempty"`
	Serial    *string  `json:"serial,omitempty"`
	NotBefore *int64   `json:"notBefore,omitempty"`
	NotAfter  *int64   `json:"notAfter,omitempty"`
	Key       *KeySpec `json:"key,omitempty"`
}

// VersionItem 版本列表项 DTO
type VersionItem struct {
	Revision       *int    `json:"revision"`
	CertID         *string `json:"certId"`
	KeyID          *string `json:"keyId"`
	Serial         *string `json:"serial"`
	Cert           *string `json:"cert"`
	EffectiveTime  *int64  `json:"effectiveTime"`
	ExpirationTime *int64  `json:"expirationTime"`
	RevocationTime *int64  `json:"revocationTime,omitempty"`
	RevocationCode *int8   `json:"revocationCode,omitempty"`
	State          *string `json:"state"`
}

// normalizeState 把"有效但已过期"修正为"已过期"，吊销优先
// 数据库只存 V/R，E 在查询时按 expiration_time 实时计算，不落库
func normalizeState(state *string, notAfter *int64) *string {
	if state == nil {
		return nil
	}
	// 吊销是终态，不覆盖
	if *state == StateRevoked {
		return state
	}
	// 有效但已过期 → E
	if *state == StateValid && notAfter != nil && *notAfter < nowMillis() {
		expired := StateExpired
		return &expired
	}
	return state
}

// ---------- 拼链 ----------

func BuildCAChain(dao *models.DB, certID string, includeRoot bool) (string, error) {
	cur, err := dao.GetCertificateByCertID(certID)
	if err != nil || cur == nil {
		return "", errors.New("certificate not found")
	}
	var out string
	for cur != nil {
		if cur.Pathlev == PathLevCA && !includeRoot {
			break
		}
		v, err := dao.GetLatestVersion(cur.CertID)
		if err != nil || v == nil {
			break
		}
		out += *v.Cert
		if cur.ParentID == nil {
			break
		}
		cur, err = dao.GetCertificateByCertID(*cur.ParentID)
		if err != nil {
			break
		}
	}
	return out, nil
}

func BuildCertChain(dao *models.DB, certID string, includeRoot bool) (string, error) {
	cert, err := dao.GetCertificateByCertID(certID)
	if err != nil || cert == nil {
		return "", errors.New("certificate not found")
	}
	v, err := dao.GetLatestVersion(certID)
	if err != nil || v == nil {
		return "", errors.New("version not found")
	}
	chain := *v.Cert
	if cert.ParentID != nil {
		caChain, err := BuildCAChain(dao, *cert.ParentID, includeRoot)
		if err != nil {
			return "", err
		}
		chain += caChain
	}
	return chain, nil
}

// FindRootCASvc 从任意证书向上找到根 CA
func FindRootCASvc(dao *models.DB, certID string) (*RootInfo, error) {
	cur, err := dao.GetCertificateByCertID(certID)
	if err != nil || cur == nil {
		return nil, errors.New("certificate not found")
	}

	chain := make([]string, 0, 4)
	var root *models.Certificate

	for {
		chain = append(chain, cur.CertID)
		if cur.ParentID == nil {
			root = cur
			break
		}
		cur, err = dao.GetCertificateByCertID(*cur.ParentID)
		if err != nil || cur == nil {
			break
		}
	}

	if root == nil {
		return nil, errors.New("root CA not found")
	}

	info := &RootInfo{
		CertID:  root.CertID,
		Title:   root.Title,
		Subject: root.Subject,
		Genre:   root.Genre,
		Pathlev: root.Pathlev,
		Chain:   chain,
	}

	// 取最新版本信息
	v, err := dao.GetLatestVersion(root.CertID)
	if err == nil && v != nil {
		info.Serial = v.Serial
		info.NotBefore = v.EffectiveTime
		info.NotAfter = v.ExpirationTime
		info.State = normalizeState(v.State, v.ExpirationTime)
	}

	return info, nil
}

// BuildRootPEM 从任意证书向上找到根 CA，返回根 CA 的 PEM
func BuildRootPEM(dao *models.DB, certID string) (string, error) {
	cur, err := dao.GetCertificateByCertID(certID)
	if err != nil || cur == nil {
		return "", errors.New("certificate not found")
	}

	// 向上遍历，直到 parent_id == nil
	for {
		if cur.ParentID == nil {
			v, err := dao.GetLatestVersion(cur.CertID)
			if err != nil || v == nil {
				return "", errors.New("root version not found")
			}
			return *v.Cert, nil
		}
		cur, err = dao.GetCertificateByCertID(*cur.ParentID)
		if err != nil || cur == nil {
			break
		}
	}
	return "", errors.New("root CA not found")
}

// ListCertsByGenres 按多个类型列出证书
// genres 为空 → 全部
func ListCertsByGenres(dao *models.DB, offset, limit int, count *int64, genres []int, hasKey int) ([]CertListItem, error) {
	certs, err := dao.ListCertificatesByGenres(offset, limit, count, genres, hasKey)
	if err != nil {
		return nil, err
	}

	items := make([]CertListItem, 0, len(certs))
	for _, c := range certs {
		item := CertListItem{
			CertID:   c.CertID,
			Title:    c.Title,
			Subject:  c.Subject,
			ParentID: c.ParentID,
			Pathlev:  c.Pathlev,
			Genre:    c.Genre,
			HasKey:   c.HasKey,
		}
		v, err := dao.GetLatestVersion(c.CertID)
		if err == nil && v != nil {
			item.Revision = v.Revision
			item.Serial = v.Serial
			item.NotBefore = v.EffectiveTime
			item.NotAfter = v.ExpirationTime
			item.State = normalizeState(v.State, v.ExpirationTime)
			if v.Cert != nil {
				if cert, perr := parseCertPEM(*v.Cert); perr == nil {
					spec := inferKeySpec(cert)
					item.Key = &spec
				}
			}
		}
		items = append(items, item)
	}
	return items, nil
}

// ListCertVersionsSvc 列出某证书的所有版本
func ListCertVersionsSvc(dao *models.DB, certID string) ([]VersionItem, error) {
	cert, err := dao.GetCertificateByCertID(certID)
	if err != nil || cert == nil {
		return nil, errors.New("certificate not found")
	}

	versions, err := dao.ListVersionsByCertID(certID)
	if err != nil {
		return nil, err
	}

	items := make([]VersionItem, 0, len(versions))
	for _, v := range versions {
		items = append(items, VersionItem{
			Revision:       v.Revision,
			CertID:         v.CertID,
			KeyID:          v.KeyID,
			Serial:         v.Serial,
			Cert:           v.Cert,
			EffectiveTime:  v.EffectiveTime,
			ExpirationTime: v.ExpirationTime,
			RevocationTime: v.RevocationTime,
			RevocationCode: v.RevocationCode,
			State:          normalizeState(v.State, v.ExpirationTime),
		})
	}
	return items, nil
}

// RootInfo 根 CA 信息
type RootInfo struct {
	CertID    string   `json:"certId"`
	Title     *string  `json:"title,omitempty"`
	Subject   *string  `json:"subject,omitempty"`
	State     *string  `json:"state,omitempty"`
	Genre     int      `json:"genre"`
	Pathlev   int      `json:"pathlev"`
	Serial    *string  `json:"serial,omitempty"`
	NotBefore *int64   `json:"notBefore,omitempty"`
	NotAfter  *int64   `json:"notAfter,omitempty"`
	Chain     []string `json:"chain"`
}
