package iputil

import (
	"net"
	"strings"
)

// Office ranges mirror Signing server/ipUtils.js (subset used for admin-ip-status labels).
var officeRanges = []struct {
	name  string
	start string
	end   string
	v6    bool
}{
	{"HR_FINANCE", "10.60.60.2", "10.60.60.254", false},
	{"IT_ADMIN", "10.85.85.2", "10.85.85.250", false},
	{"2ND_FLOOR_A", "10.20.20.10", "10.20.20.250", false},
}

func ipv4ToInt(ip string) (uint32, bool) {
	p := net.ParseIP(strings.TrimSpace(ip))
	if p == nil || p.To4() == nil {
		return 0, false
	}
	v4 := p.To4()
	return uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3]), true
}

func isOfficeIPv4(ip string) bool {
	clean := strings.TrimPrefix(strings.ToLower(ip), "::ffff:")
	addr, ok := ipv4ToInt(clean)
	if !ok {
		return false
	}
	for _, r := range officeRanges {
		if r.v6 {
			continue
		}
		lo, _ := ipv4ToInt(r.start)
		hi, _ := ipv4ToInt(r.end)
		if addr >= lo && addr <= hi {
			return true
		}
	}
	return false
}

func IsOnOfficeNetwork(serverSeenIP string, workstationIPs []string) bool {
	candidates := []string{}
	if t := strings.TrimSpace(serverSeenIP); t != "" && t != "unknown" {
		candidates = append(candidates, t)
	}
	for _, w := range workstationIPs {
		if t := strings.TrimSpace(w); t != "" {
			candidates = append(candidates, t)
		}
	}
	for _, ip := range candidates {
		if isOfficeIPv4(ip) {
			return true
		}
	}
	return false
}

func OfficeNetworkLabel(serverSeenIP string, workstationIPs []string) string {
	candidates := []string{}
	if t := strings.TrimSpace(serverSeenIP); t != "" && t != "unknown" {
		candidates = append(candidates, t)
	}
	for _, w := range workstationIPs {
		if t := strings.TrimSpace(w); t != "" {
			candidates = append(candidates, t)
		}
	}
	for _, ip := range candidates {
		clean := strings.TrimPrefix(strings.ToLower(ip), "::ffff:")
		addr, ok := ipv4ToInt(clean)
		if !ok {
			continue
		}
		for _, r := range officeRanges {
			if r.v6 {
				continue
			}
			lo, _ := ipv4ToInt(r.start)
			hi, _ := ipv4ToInt(r.end)
			if addr >= lo && addr <= hi {
				return r.name
			}
		}
	}
	return ""
}
