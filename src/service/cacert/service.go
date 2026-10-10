package cacert

import (
	"crypto/x509"
	"time"
)

// nowMillis 毫秒时间戳
func nowMillis() int64 { return time.Now().UnixMilli() }

// extKeyUsageNames 扩展密钥用途 常量 → 字符串
var extKeyUsageNames = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageServerAuth:      "serverAuth",
	x509.ExtKeyUsageClientAuth:      "clientAuth",
	x509.ExtKeyUsageCodeSigning:     "codeSigning",
	x509.ExtKeyUsageEmailProtection: "emailProtection",
	x509.ExtKeyUsageTimeStamping:    "timeStamping",
	x509.ExtKeyUsageOCSPSigning:     "ocspSigning",
	x509.ExtKeyUsageIPSECEndSystem:  "ipsecEndSystem",
	x509.ExtKeyUsageIPSECTunnel:     "ipsecTunnel",
	x509.ExtKeyUsageIPSECUser:       "ipsecUser",
}

// extKeyUsageToStrings []x509.ExtKeyUsage → []string
func extKeyUsageToStrings(eku []x509.ExtKeyUsage) []string {
	var out []string
	for _, e := range eku {
		if name, ok := extKeyUsageNames[e]; ok {
			out = append(out, name)
		}
	}
	return out
}
