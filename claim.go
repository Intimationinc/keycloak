package keycloak

import (
	"github.com/dgrijalva/jwt-go/v4"
	"gopkg.in/guregu/null.v3"
)

// Claim keycloak jwt token
type Claim struct {
	clientID, iss string
	jwt.StandardClaims
	AuthorizedParty     string   `json:"azp"`
	Name                string   `json:"name"`
	Email               string   `json:"email"`
	EmailVerified       bool     `json:"email_verified"`
	PhoneNumber         string   `json:"phone_number"`
	PhoneNumberVerified bool     `json:"phone_number_verified"`
	Plan                string   `json:"plan"`
	Groups              string   `json:"groups"`
	LocalUserID         null.Int `json:"local_user_id"`
}

// Valid validate the jwt token
func (cl *Claim) Valid(h *jwt.ValidationHelper) error {
	if h == nil {
		h = jwt.DefaultValidationHelper
	}
	if cl.AuthorizedParty != cl.clientID {
		return ErrInvalidToken
	}

	return nil
}
