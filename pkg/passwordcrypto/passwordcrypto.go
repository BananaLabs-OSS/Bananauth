// Package passwordcrypto owns stateless password hashing and verification.
package passwordcrypto

import "golang.org/x/crypto/bcrypt"

func Hash(password string) (string, error) {
	value, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(value), err
}

func Verify(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}
