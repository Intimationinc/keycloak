package keycloak

import (
	"time"

	"github.com/dgrijalva/jwt-go"
	"gopkg.in/guregu/null.v3"
)

// Claim keycloak jwt token
type Claim struct {
	clientID, iss string
	Role          Role
	jwt.StandardClaims
	AuthorizedParty     string   `json:"azp"`
	Name                string   `json:"name"`
	Email               string   `json:"email"`
	EmailVerified       bool     `json:"email_verified"`
	PhoneNumber         string   `json:"phone_number"`
	PhoneNumberVerified bool     `json:"phone_number_verified"`
	Plan                string   `json:"plan"`
	LocalUserID         null.Int `json:"local_user_id"`
	ResourceAccess      map[string]struct {
		Roles []string `json:"roles"`
	} `json:"resource_access"`
}

// Valid validate the jwt token
func (cl *Claim) Valid() error {
	now := time.Now().Unix()
	if !cl.VerifyExpiresAt(now, true) || !cl.VerifyIssuedAt(now, true) || !cl.VerifyIssuer(cl.iss, true) || cl.AuthorizedParty != cl.clientID {
		return ErrInvalidToken
	}

	found := false
	for _, r := range cl.ResourceAccess[cl.clientID].Roles {
		if cl.Role == Role(r) {
			found = true
			break
		}
	}
	if !found {
		return ErrInvalidToken
	}
	return nil
}
