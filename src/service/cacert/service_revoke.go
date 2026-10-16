package cacert

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"spki/src/models"
	"strconv"
	"strings"
	"time"
)

// ---------- 吊销 ----------

func RevokeCertSvc(dao *models.DB, certID string) error {
	cert, err := dao.GetCertificateByCertID(certID)
	if err != nil || cert == nil {
		return errors.New("certificate not found")
	}
	now := nowMillis()
	return dao.RevokeCertTx(certID, StateRevoked, now)
}

// ---------- 删除 ----------

func DeleteCertSvc(dao *models.DB, certID string) error {
	return dao.DeleteCertTx(certID)
}

// ---------- CRL ----------

// isInvalidExpiryErr 判断是否为有效期格式错误（用于返回 400）。
func isInvalidExpiryErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "invalid expiry") ||
		strings.Contains(msg, "empty expiry") ||
		strings.Contains(msg, "unsupported unit")
}

// parseExpiry 解析 "1d" / "1m" / "1y" 形式的有效期，返回 NextUpdate 时间。
//   - d: 自然日
//   - m: 自然月（钳制到目标月最后一天，如平年 1/29 +1m = 2/28）
//   - y: 自然年（钳制，如闰年 2/29 +1y = 次年 2/28）
func parseExpiry(now time.Time, s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, errors.New("empty expiry")
	}

	re := regexp.MustCompile(`^(\d+)([dmy])$`)
	m := re.FindStringSubmatch(s)
	if m == nil {
		return time.Time{}, fmt.Errorf("invalid expiry %q, expected like 1d / 1m / 1y", s)
	}

	n, err := strconv.Atoi(m[1])
	if err != nil || n <= 0 {
		return time.Time{}, fmt.Errorf("invalid expiry number in %q", s)
	}

	switch m[2] {
	case "d":
		return now.AddDate(0, 0, n), nil
	case "m":
		return addMonthsClamp(now, n), nil
	case "y":
		return addYearsClamp(now, n), nil
	default:
		return time.Time{}, fmt.Errorf("unsupported unit %q", m[2])
	}
}

// addMonthsClamp 在 now 基础上加 months 个自然月；
// 若目标月没有对应的"日"，则钳制到目标月最后一天。
// 例：2025-01-29 +1m = 2025-02-28；2024-01-31 +1m = 2024-02-29。
func addMonthsClamp(now time.Time, months int) time.Time {
	y, mo, d := now.Date()
	h, mi, sec := now.Clock()
	ns := now.Nanosecond()
	loc := now.Location()

	// 目标月第一天
	first := time.Date(y, mo+time.Month(months), 1, h, mi, sec, ns, loc)
	// 目标月最后一天
	lastDay := first.AddDate(0, 1, -1).Day()
	if d > lastDay {
		d = lastDay
	}
	return time.Date(first.Year(), first.Month(), d, h, mi, sec, ns, loc)
}

// addYearsClamp 在 now 基础上加 years 个自然年；
// 若目标年没有对应的"日"（闰年 2/29），则钳制到 2/28。
func addYearsClamp(now time.Time, years int) time.Time {
	y, mo, d := now.Date()
	h, mi, sec := now.Clock()
	ns := now.Nanosecond()
	loc := now.Location()

	targetYear := y + years
	// 目标年该月最后一天
	lastDay := time.Date(targetYear, mo+1, 0, h, mi, sec, ns, loc).Day()
	if d > lastDay {
		d = lastDay
	}
	return time.Date(targetYear, mo, d, h, mi, sec, ns, loc)
}

// BuildCRL 构建并签名 CRL。
// validFor 形如 "1d" / "1m" / "1y"；为空时默认 "7d"。
func BuildCRL(dao *models.DB, issuerID string, validFor string) (string, error) {
	if validFor == "" {
		validFor = "7d"
	}

	now := time.Now()
	nextUpdate, err := parseExpiry(now, validFor)
	if err != nil {
		return "", err
	}

	issuer, err := dao.GetCertificateByCertID(issuerID)
	if err != nil || issuer == nil {
		return "", errors.New("issuer not found")
	}
	issuerVer, err := dao.GetLatestVersion(issuerID)
	if err != nil || issuerVer == nil {
		return "", errors.New("issuer version not found")
	}

	if issuerVer.KeyID == nil {
		return "", errors.New("issuer CA has no private key, cannot sign CRL")
	}

	issuerKeyRec, err := dao.GetPrivateKeyByKeyID(*issuerVer.KeyID)
	if err != nil || issuerKeyRec == nil {
		return "", errors.New("issuer key not found")
	}
	issuerCert, err := parseCertPEM(*issuerVer.Cert)
	if err != nil {
		return "", err
	}
	signer, err := decryptPrivateKey(issuerKeyRec.PrivateKey, issuerKeyRec.Passphrase)
	if err != nil {
		return "", err
	}

	revoked, err := dao.ListRevokedByIssuer(issuerID)
	if err != nil {
		return "", err
	}

	var entries []x509.RevocationListEntry
	for _, v := range revoked {
		if v.Serial == nil || v.RevocationTime == nil {
			continue
		}
		serial := new(big.Int)
		if _, ok := serial.SetString(*v.Serial, 16); !ok {
			continue
		}
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: time.UnixMilli(*v.RevocationTime),
		})
	}

	template := &x509.RevocationList{
		Number:                    big.NewInt(now.UnixNano()),
		ThisUpdate:                now,
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: entries,
	}

	der, err := x509.CreateRevocationList(rand.Reader, template, issuerCert, signer)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})), nil
}
