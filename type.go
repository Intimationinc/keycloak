package keycloak

// Role of auth user
type Role string

// String method for string value
func (r Role) String() string {
	return string(r)
}

// KeycloakUser keycloak create user
type KeycloakUser struct {
	ID          string
	LocalUserID string
	Name        string
	Email       string
	Role        Role
	Attribute   map[string][]string
}

// KeycloakUserUpdate update keycloak user
type KeycloakUserUpdate struct {
	Name    *string
	Email   *string
	Enabled *bool
	Plan    *string
}
