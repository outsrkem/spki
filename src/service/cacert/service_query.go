package cacert

import (
	"errors"
	"spki/src/models"
)

// CertListItem 列表项 DTO
type CertListItem struct {
	CertID    string  `json:"certId"`
	Title     *string `json:"title,omitempty"`
	Subject   *string `json:"subject,omitempty"`
	State     *string `json:"state,omitempty"`
	ParentID  *string `json:"parentId,omitempty"`
	Pathlev   int     `json:"pathlev"`
	Genre     int     `json:"genre"`
	Revision  *int    `json:"revision,omitempty"`
	Serial    *string `json:"serial,omitempty"`
	NotBefore *int64  `json:"notBefore,omitempty"`
	NotAfter  *int64  `json:"notAfter,omitempty"`
	Alarm     *int8   `json:"alarm,omitempty"`
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
	Alarm          *int8   `json:"alarm"`
	State          *string `json:"state"`
}

// ---------- 拼链 ----------

func BuildCAChain(certID string, includeRoot bool) (string, error) {
	cur, err := models.GetCertificateByCertID(certID)
	if err != nil || cur == nil {
		return "", errors.New("certificate not found")
	}
	var out string
	for cur != nil {
		if cur.Pathlev == PathLevCA && !includeRoot {
			break
		}
		v, err := models.GetLatestVersion(cur.CertID)
		if err != nil || v == nil {
			break
		}
		out += *v.Cert
		if cur.ParentID == nil {
			break
		}
		cur, err = models.GetCertificateByCertID(*cur.ParentID)
		if err != nil {
			break
		}
	}
	return out, nil
}

func BuildCertChain(certID string, includeRoot bool) (string, error) {
	cert, err := models.GetCertificateByCertID(certID)
	if err != nil || cert == nil {
		return "", errors.New("certificate not found")
	}
	v, err := models.GetLatestVersion(certID)
	if err != nil || v == nil {
		return "", errors.New("version not found")
	}
	chain := *v.Cert
	if cert.ParentID != nil {
		caChain, err := BuildCAChain(*cert.ParentID, includeRoot)
		if err != nil {
			return "", err
		}
		chain += caChain
	}
	return chain, nil
}

// FindRootCASvc 从任意证书向上找到根 CA
func FindRootCASvc(certID string) (*RootInfo, error) {
	cur, err := models.GetCertificateByCertID(certID)
	if err != nil || cur == nil {
		return nil, errors.New("certificate not found")
	}

	chain := make([]string, 0, 4)
	var root *models.Certificate

	for cur != nil {
		chain = append(chain, cur.CertID)
		if cur.ParentID == nil {
			root = cur
			break
		}
		cur, err = models.GetCertificateByCertID(*cur.ParentID)
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
	v, err := models.GetLatestVersion(root.CertID)
	if err == nil && v != nil {
		info.Serial = v.Serial
		info.NotBefore = v.EffectiveTime
		info.NotAfter = v.ExpirationTime
		info.State = v.State
	}

	return info, nil
}

// BuildRootPEM 从任意证书向上找到根 CA，返回根 CA 的 PEM
func BuildRootPEM(certID string) (string, error) {
	cur, err := models.GetCertificateByCertID(certID)
	if err != nil || cur == nil {
		return "", errors.New("certificate not found")
	}

	// 向上遍历，直到 parent_id == nil
	for cur != nil {
		if cur.ParentID == nil {
			v, err := models.GetLatestVersion(cur.CertID)
			if err != nil || v == nil {
				return "", errors.New("root version not found")
			}
			return *v.Cert, nil
		}
		cur, err = models.GetCertificateByCertID(*cur.ParentID)
		if err != nil || cur == nil {
			break
		}
	}
	return "", errors.New("root CA not found")
}

// ListCertsByGenres 按多个类型列出证书
// genres 为空 → 全部
func ListCertsByGenres(genres []int, userID string) ([]CertListItem, error) {
	certs, err := models.ListCertificatesByGenres(genres, userID)
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
		}
		v, err := models.GetLatestVersion(c.CertID)
		if err == nil && v != nil {
			item.Revision = v.Revision
			item.Serial = v.Serial
			item.NotBefore = v.EffectiveTime
			item.NotAfter = v.ExpirationTime
			item.Alarm = v.Alarm
			item.State = v.State
		}
		items = append(items, item)
	}
	return items, nil
}

// ListCertVersionsSvc 列出某证书的所有版本
func ListCertVersionsSvc(certID string) ([]VersionItem, error) {
	cert, err := models.GetCertificateByCertID(certID)
	if err != nil || cert == nil {
		return nil, errors.New("certificate not found")
	}

	versions, err := models.ListVersionsByCertID(certID)
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
			Alarm:          v.Alarm,
			State:          v.State,
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
