package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/scrypt"
)

// HashPassword matches Node database.js: scrypt$N$r$p$saltB64$hashB64
func HashPassword(password string) (string, error) {
	const N = 1 << 14
	const r = 8
	const p = 1
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	derived, err := scrypt.Key([]byte(password), salt, N, r, p, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("scrypt$%d$%d$%d$%s$%s",
		N, r, p,
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(derived),
	), nil
}

func VerifyPassword(password, stored string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 6 || parts[0] != "scrypt" {
		return false
	}
	N, _ := strconv.Atoi(parts[1])
	r, _ := strconv.Atoi(parts[2])
	p, _ := strconv.Atoi(parts[3])
	salt, err := base64.StdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	hash, err := base64.StdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	derived, err := scrypt.Key([]byte(password), salt, N, r, p, len(hash))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(hash, derived) == 1
}
