package domain

import "golang.org/x/crypto/bcrypt"

// UserInfo holds information about a user, including authentication and metadata.
type UserInfo struct {
	Unix       Unix
	Biometrics Biometrics
	Basic      Basic
	External   External
}

// Unix contains Linux/Unix specific information about the user.
type Unix struct {
	UID                string
	User               string
	GID                string
	Group              string
	SupplementaryGroups []SupplementaryGroup
}

// SupplementaryGroup represents additional groups the user belongs to.
type SupplementaryGroup struct {
	GID   string
	Group string
}

// Basic holds basic authentication details.
type Basic struct {
	UserName     string
	PasswordHash string // Store a hash instead of plain text passwords.
}

// SetPassword hashes the password and stores the hash in PasswordHash.
func (b *Basic) SetPassword(password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	b.PasswordHash = string(hash)
	return nil
}

// ValidatePassword compares the provided password with the stored hash.
func (b *Basic) ValidatePassword(password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(b.PasswordHash), []byte(password))
	return err == nil
}

// Biometrics holds biometric data for user authentication.
// TO BE IMPLEMENTED
type Biometrics struct{}

// External holds external authentication data.
// TO BE IMPLEMENTED
type External struct{}
