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
	"spki/src/pkg/answer"
	"strconv"
	"strings"
	"time"
)

// ---------- 吊销 ----------

func RevokeCertSvc(dao *models.DB, certID string, reason int8) error {
	if !models.IsValidRevocationCode(reason) {
		return ErrBadRequest(answer.EcodeInvalidRevocationReason, "invalid revocation code", nil)
	}
	cert, err := dao.GetCertificateByCertID(certID)
	if err != nil {
		return ErrInternal(answer.EcodeError, "query cert failed", err)
	}
	if cert == nil {
		return ErrNotFound(answer.EcodeCertificate404, "certificate not found", nil)
	}
	if v, err := dao.GetLatestVersion(certID); err == nil && v != nil &&
		v.State != nil && *v.State == models.StateRevoked {
		return nil
	}
	now := nowMillis()
	if err := dao.RevokeCertTx(certID, StateRevoked, now, reason); err != nil {
		return ErrInternal(answer.EcodeError, "revoke cert failed", err)
	}
	return nil
}

// ---------- 删除 ----------

// DeleteCertSvc 删除证书
func DeleteCertSvc(dao *models.DB, certID string) error {
	if err := dao.DeleteCertTx(certID); err != nil {
		if errors.Is(err, models.ErrHasChildren) {
			return ErrConflict(answer.EcodeDeleteResourceConflict, "CA has sub-certificates, cannot delete", err)
		}
		return ErrInternal(answer.EcodeError, "delete cert failed", err)
	}
	return nil
}

// ---------- CRL ----------

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
		return "", ErrBadRequest(answer.EcodeInvalidExpiry, "invalid validFor", err)
	}

	issuer, err := dao.GetCertificateByCertID(issuerID)
	if err != nil {
		return "", ErrInternal(answer.EcodeError, "query issuer failed", err)
	}
	if issuer == nil {
		return "", ErrNotFound(answer.EcodeIssuer404, "issuer not found", nil)
	}
	issuerVer, err := dao.GetLatestVersion(issuerID)
	if err != nil {
		return "", ErrInternal(answer.EcodeError, "query issuer version failed", err)
	}
	if issuerVer == nil {
		return "", ErrNotFound(answer.EcodeVersion404, "issuer version not found", nil)
	}

	if issuerVer.KeyID == nil {
		return "", ErrBadRequest(answer.EcodeCACannotSign, "issuer CA has no private key, cannot sign CRL", nil)
	}

	issuerKeyRec, err := dao.GetPrivateKeyByKeyID(*issuerVer.KeyID)
	if err != nil {
		return "", ErrInternal(answer.EcodeError, "query issuer key failed", err)
	}
	if issuerKeyRec == nil {
		return "", ErrNotFound(answer.EcodePrivateKey404, "issuer key not found", nil)
	}
	issuerCert, err := parseCertPEM(*issuerVer.Cert)
	if err != nil {
		return "", ErrInternal(answer.EcodeError, "parse issuer cert failed", err)
	}
	signer, err := decryptPrivateKey(issuerKeyRec.PrivateKey, issuerKeyRec.Passphrase)
	if err != nil {
		return "", ErrInternal(answer.EcodeError, "decrypt issuer key failed", err)
	}

	revoked, err := dao.ListRevokedByIssuer(issuerID)
	if err != nil {
		return "", ErrInternal(answer.EcodeError, "list revoked failed", err)
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
		entry := x509.RevocationListEntry{
			SerialNumber:   serial,
			RevocationTime: time.UnixMilli(*v.RevocationTime),
		}
		// 0 或 nil 不写 reasonCode（符合 RFC 5280）
		if v.RevocationCode != nil && *v.RevocationCode != models.ReasonUnspecified {
			entry.ReasonCode = int(*v.RevocationCode)
		}
		entries = append(entries, entry)
	}

	template := &x509.RevocationList{
		Number:                    big.NewInt(now.UnixNano()),
		ThisUpdate:                now,
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: entries,
	}

	der, err := x509.CreateRevocationList(rand.Reader, template, issuerCert, signer)
	if err != nil {
		return "", ErrInternal(answer.EcodeError, "create CRL failed", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})), nil
}
