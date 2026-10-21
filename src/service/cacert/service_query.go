package cacert

import (
	"spki/src/models"
	"spki/src/pkg/answer"
	"strings"
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
	Chain     string   `json:"chain,omitempty"`
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

// extractCNFromSubject 从 formatSubject 生成的字符串里取 CN
// 形如 "/C=CN/O=PrivateSign/OU=PrivateSign/CN=AAA PrivateSign Root CA"
// CN 由 formatSubject 保证是最后一个 RDN
func extractCNFromSubject(subject string) string {
	const marker = "/CN="
	i := strings.LastIndex(subject, marker)
	if i < 0 {
		return ""
	}
	cn := subject[i+len(marker):]
	if j := strings.Index(cn, "/"); j >= 0 {
		cn = cn[:j]
	}
	return cn
}

// resolveCertChain 从 certID 向上走到根，返回 CN 链（根在前，末端在后）
// 结果按 certID 缓存在 cache 里；visited 用于环检测
func resolveCertChain(dao *models.DB, certID string, cache map[string][]string, visited map[string]bool) []string {
	if chain, ok := cache[certID]; ok {
		return chain
	}
	if visited[certID] {
		return nil
	}
	visited[certID] = true

	cert, err := dao.GetCertificateByCertID(certID)
	if err != nil || cert == nil {
		cache[certID] = nil
		return nil
	}

	cn := ""
	if cert.Subject != nil {
		cn = extractCNFromSubject(*cert.Subject)
	}

	if cn == "" {
		if v, verr := dao.GetLatestVersion(certID); verr == nil && v != nil && v.Cert != nil {
			if xc, perr := parseCertPEM(*v.Cert); perr == nil {
				cn = xc.Subject.CommonName
			}
		}
	}

	var chain []string
	if cert.ParentID != nil {
		chain = append(chain, resolveCertChain(dao, *cert.ParentID, cache, visited)...)
	}
	if cn != "" {
		chain = append(chain, cn)
	}

	cache[certID] = chain
	return chain
}

func normalizeState(state *string, notAfter *int64) *string {
	if state == nil {
		return nil
	}
	if *state == StateRevoked {
		return state
	}
	if *state == StateValid && notAfter != nil && *notAfter < nowMillis() {
		expired := StateExpired
		return &expired
	}
	return state
}

// ---------- 拼链 ----------

func BuildCAChain(dao *models.DB, certID string, includeRoot bool) (string, error) {
	cur, err := dao.GetCertificateByCertID(certID)
	if err != nil {
		return "", ErrInternal(answer.EcodeError, "query cert failed", err)
	}
	if cur == nil {
		return "", ErrNotFound(answer.EcodeCertificate404, "certificate not found", nil)
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
	if err != nil {
		return "", ErrInternal(answer.EcodeError, "query cert failed", err)
	}
	if cert == nil {
		return "", ErrNotFound(answer.EcodeCertificate404, "certificate not found", nil)
	}
	v, err := dao.GetLatestVersion(certID)
	if err != nil {
		return "", ErrInternal(answer.EcodeError, "query version failed", err)
	}
	if v == nil {
		return "", ErrNotFound(answer.EcodeVersion404, "version not found", nil)
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
	if err != nil {
		return nil, ErrInternal(answer.EcodeError, "query cert failed", err)
	}
	if cur == nil {
		return nil, ErrNotFound(answer.EcodeCertificate404, "certificate not found", nil)
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
		return nil, ErrNotFound(answer.EcodeRootCANotFound, "root CA not found", nil)
	}

	info := &RootInfo{
		CertID:  root.CertID,
		Title:   root.Title,
		Subject: root.Subject,
		Genre:   root.Genre,
		Pathlev: root.Pathlev,
		Chain:   chain,
	}

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
	if err != nil {
		return "", ErrInternal(answer.EcodeError, "query cert failed", err)
	}
	if cur == nil {
		return "", ErrNotFound(answer.EcodeCertificate404, "certificate not found", nil)
	}

	for {
		if cur.ParentID == nil {
			v, err := dao.GetLatestVersion(cur.CertID)
			if err != nil {
				return "", ErrInternal(answer.EcodeError, "query version failed", err)
			}
			if v == nil {
				return "", ErrNotFound(answer.EcodeVersion404, "root version not found", nil)
			}
			return *v.Cert, nil
		}
		cur, err = dao.GetCertificateByCertID(*cur.ParentID)
		if err != nil {
			return "", ErrInternal(answer.EcodeError, "query parent cert failed", err)
		}
		if cur == nil {
			return "", ErrNotFound(answer.EcodeCertificate404, "parent cert not found", nil)
		}
	}
}

// ListCertsByGenres 按多个类型列出证书
func ListCertsByGenres(dao *models.DB, offset, limit int, count *int64, genres []int, hasKey int) ([]CertListItem, error) {
	certs, err := dao.ListCertificatesByGenres(offset, limit, count, genres, hasKey)
	if err != nil {
		return nil, ErrInternal(answer.EcodeError, "list certs failed", err)
	}

	chainCache := make(map[string][]string, len(certs))

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
		// 拼证书链信息
		item.Chain = strings.Join(
			resolveCertChain(dao, c.CertID, chainCache, make(map[string]bool)),
			"/",
		)

		items = append(items, item)
	}
	return items, nil
}

// ListCertVersionsSvc 列出某证书的所有版本
func ListCertVersionsSvc(dao *models.DB, certID string) ([]VersionItem, error) {
	cert, err := dao.GetCertificateByCertID(certID)
	if err != nil {
		return nil, ErrInternal(answer.EcodeError, "query cert failed", err)
	}
	if cert == nil {
		return nil, ErrNotFound(answer.EcodeCertificate404, "certificate not found", nil)
	}

	versions, err := dao.ListVersionsByCertID(certID)
	if err != nil {
		return nil, ErrInternal(answer.EcodeError, "list versions failed", err)
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
