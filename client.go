package keycloak

import (
	"errors"
	"sync"
	"time"

	"github.com/Nerzal/gocloak/v5"
	"github.com/sirupsen/logrus"
)

// cleint errors
var (
	ErrInvalidToken   = errors.New("invalid token")
	ErrClientNotFound = errors.New("client not found")
	ErrRoleNotFound   = errors.New("role not found")
	ErrUserNotFound   = errors.New("user not found")
)

const adminClientID = "admin-cli"

// Config configs for keycloak
type Config struct {
	Host          string `json:"host"`
	AdminUser     string `json:"admin_user"`
	AdminPassword string `json:"admin_password"`
	AdminRealm    string `json:"admin_realm"`
	AdminSecret   string `json:"admin_secret"`
	ClientID      string `json:"client_id"`
	ClientSecret  string `json:"client_secret"`
	ClientRealm   string `json:"client_realm"`
}

type keycloakClient struct {
	id       string
	clientID string
}

type adminClient struct {
	mu            sync.RWMutex
	admin         *gocloak.JWT
	accessExpiry  time.Time
	refreshExpiry time.Time
}

// Client keycloak client
type Client struct {
	cfg    Config
	kc     gocloak.GoCloak
	ac     *adminClient
	client keycloakClient
	realm  string
	iss    string
	l      *logrus.Logger
}

// NewClient instantiate keycloak client
func NewClient(cfg Config, l *logrus.Logger) (*Client, error) {
	kClient := gocloak.NewClient(cfg.Host)
	admin, err := kClient.Login(adminClientID, cfg.AdminSecret, cfg.AdminRealm, cfg.AdminUser, cfg.AdminPassword)
	if err != nil {
		l.Errorf("NewClient", err, "failed to log admin user in")
		return nil, err
	}
	clients, err := kClient.GetClients(admin.AccessToken, cfg.ClientRealm, gocloak.GetClientsParams{ClientID: &cfg.ClientID})
	if err != nil {
		return nil, err
	}
	if len(clients) == 0 {
		return nil, ErrClientNotFound
	}

	return &Client{
		cfg: cfg,
		kc:  kClient,
		ac: &adminClient{
			admin:         admin,
			accessExpiry:  time.Now().Add(time.Second * time.Duration(admin.ExpiresIn)),
			refreshExpiry: time.Now().Add(time.Second * time.Duration(admin.RefreshExpiresIn)),
		},
		client: keycloakClient{
			id:       *clients[0].ID,
			clientID: *clients[0].ClientID,
		},
		realm: cfg.ClientRealm,
		iss:   cfg.Host + "/auth/realms/" + cfg.ClientRealm,
		l:     l,
	}, nil
}

// RefreshAdmin validateAdmin this function will check for the admin AccessToken and RefreshToken and will update tokens as necessary
func (c *Client) RefreshAdmin() error {
	var admin *gocloak.JWT
	var err error

	c.ac.mu.Lock()
	defer c.ac.mu.Unlock()

	if time.Now().Before(c.ac.refreshExpiry) {
		admin, err = c.kc.RefreshToken(c.ac.admin.RefreshToken, adminClientID, c.cfg.AdminSecret, c.cfg.AdminRealm)
		if err != nil {
			c.l.Errorf("RefreshAdmin", err, "failed to refresh admin token")
			return err
		}
	} else {
		admin, err = c.kc.Login(adminClientID, c.cfg.AdminSecret, c.cfg.AdminRealm, c.cfg.AdminUser, c.cfg.AdminPassword)
		if err != nil {
			c.l.Errorf("RefreshAdmin", err, "failed to login admin")
			return err
		}
	}

	c.ac.admin = admin
	c.ac.accessExpiry = time.Now().Add(time.Second * time.Duration(admin.ExpiresIn))
	c.ac.refreshExpiry = time.Now().Add(time.Second * time.Duration(admin.RefreshExpiresIn))
	c.l.Info("RefreshAdmin: tokens are active")
	return nil
}

// AdminExpiresIn time left to expire the admin token
func (c *Client) AdminExpiresIn() time.Duration {
	c.ac.mu.RLock()
	defer c.ac.mu.RUnlock()

	return c.ac.accessExpiry.Sub(time.Now())
}

// CreateUser create kc user
func (c *Client) CreateUser(user *KeycloakUser, password string) error {
	roles := []gocloak.Role{}

	c.ac.mu.RLock()
	defer c.ac.mu.RUnlock()

	rls, err := c.kc.GetClientRoles(c.ac.admin.AccessToken, c.realm, c.client.id)
	if err != nil {
		c.l.Errorf("CreateUser: failed getting client roles ", err)
		return err
	}

	// check if client has all required role to assign user
	found := false
	for _, rl := range rls {
		if *rl.Name == string(user.Role) {
			roles = append(roles, *rl)
			found = true
			break
		}
	}
	if !found {
		return ErrRoleNotFound
	}

	user.ID, err = c.kc.CreateUser(c.ac.admin.AccessToken, c.realm, gocloak.User{
		Username:      &user.Email,
		Email:         &user.Email,
		EmailVerified: gocloak.BoolP(false),
		Enabled:       gocloak.BoolP(true),
		FirstName:     &user.Name,
		Attributes: map[string][]string{
			"phoneNumber":         {user.Phone},
			"phoneNumberVerified": {"false"},
			"plan":                {user.Plan},
			"local_user_id":       {user.LocalUserID},
			"role":                {user.Role.String()},
		},
		Credentials: []*gocloak.CredentialRepresentation{
			{
				Temporary: gocloak.BoolP(false),
				Type:      gocloak.StringP("password"),
				Value:     &password,
			},
		},
	})
	if err != nil {
		c.l.Errorf("CreateUser: failed creating user: %s", user.Email)
		return err
	}

	err = c.kc.AddClientRoleToUser(c.ac.admin.AccessToken, c.realm, c.client.id, user.ID, roles)
	if err != nil {
		c.l.Errorf("CreateUser: failed adding role to user: %s", user.ID)
		return err
	}
	return nil
}

// Login keycloack account login
func (c *Client) Login(username, password string) (*gocloak.JWT, error) {
	// c.l.Started("Login")
	t, err := c.kc.Login(c.client.clientID, c.cfg.ClientSecret, c.realm, username, password)
	if err != nil {
		c.l.Errorf("Login", err, "failed login %s", username)
		return nil, err
	}
	return t, nil
}

// Refresh an active refreshToken
// only used for the clients
func (c *Client) Refresh(refreshToken string) (*gocloak.JWT, error) {
	// c.l.Started("Refresh")
	t, err := c.kc.RefreshToken(refreshToken, c.client.clientID, c.cfg.ClientSecret, c.realm)
	if err != nil {
		// c.l.Errorf("Refresh", err, "failed refresh")
		return nil, err
	}
	// c.l.Completed("Refresh")
	return t, nil
}

// Logout scope of this method is revoke user refresh token
func (c *Client) Logout(refreshToken string) error {
	err := c.kc.Logout(c.client.clientID, c.cfg.ClientSecret, c.realm, refreshToken)
	if err != nil {
		c.l.Errorf("Logout", err, "failed logout")
		return err
	}
	return nil
}

// CheckEnabled check if the user is enabled
func (c *Client) CheckEnabled(userID string) (bool, error) {
	c.ac.mu.RLock()
	defer c.ac.mu.RUnlock()

	user, err := c.kc.GetUserByID(c.ac.admin.AccessToken, c.realm, userID)
	if err != nil {
		c.l.Errorf("CheckEnabled", err, "failed to get user: %s", userID)
		return false, err
	}
	return *user.Enabled, nil
}

// UpdateUser update the keycloak user
func (c *Client) UpdateUser(userID string, user KeycloakUserUpdate) error {
	c.ac.mu.RLock()
	defer c.ac.mu.RUnlock()

	var attr map[string][]string
	if user.Plan != nil {
		u, err := c.kc.GetUserByID(c.ac.admin.AccessToken, c.realm, userID)
		if err != nil {
			c.l.Errorf("UpdateUser", err, "failed to get user: %s", userID)
			return err
		}
		attr = u.Attributes
		attr["plan"] = []string{*user.Plan}
	}

	err := c.kc.UpdateUser(c.ac.admin.AccessToken, c.realm, gocloak.User{
		FirstName:  user.Name,
		Email:      user.Email,
		Enabled:    user.Enabled,
		Attributes: attr,
	})
	if err != nil {
		c.l.Errorf("UpdateUser", err, "failed to update user: %s", userID)
	}
	return err
}

// SetEmailVerified will be used to verify email
func (c *Client) SetEmailVerified(userID string) error {
	c.ac.mu.RLock()
	defer c.ac.mu.RUnlock()

	_, err := c.kc.GetUserByID(c.ac.admin.AccessToken, c.realm, userID)
	if err != nil {
		c.l.Errorf("SetEmailVerified", err, "failed to get user: %s", userID)
		return err
	}
	err = c.kc.UpdateUser(c.ac.admin.AccessToken, c.realm, gocloak.User{
		EmailVerified: gocloak.BoolP(true),
	})
	if err != nil {
		c.l.Errorf("SetEmailVerified", err, "failed to update email-verified with user_id: %s", userID)
	}
	return err
}

// GetUserByPhoneNumber get user details by phone number
func (c *Client) GetUserByPhoneNumber(phone string) (*gocloak.User, error) {
	c.ac.mu.RLock()
	defer c.ac.mu.RUnlock()

	user, err := c.kc.GetUsers(c.ac.admin.AccessToken, c.realm, gocloak.GetUsersParams{Username: &phone})
	if err != nil {
		c.l.Errorf("GetUserByPhoneNumber", err, "failed to get user by %s", phone)
		return nil, err
	}
	if len(user) == 0 {
		c.l.Errorf("GetUserByPhoneNumber", err, "failed to get user by %s", phone)
		return nil, ErrUserNotFound
	}
	return user[0], nil
}

// ResetPassword reset password for users
func (c *Client) ResetPassword(userID, password string) error {
	c.ac.mu.RLock()
	defer c.ac.mu.RUnlock()
	err := c.kc.SetPassword(c.ac.admin.AccessToken, userID, c.realm, password, false)
	if err != nil {
		c.l.Errorf("ResetPassword", err, "failed to update password with user_id: %s", userID)
		return err
	}
	return nil
}

// VerifyToken verify the user token
func (c *Client) VerifyToken(accessToken string) (*Claim, error) {
	claim := &Claim{
		clientID: c.client.clientID,
		iss:      c.iss,
	}

	_, err := c.kc.DecodeAccessTokenCustomClaims(accessToken, c.realm, claim)
	if err != nil {
		c.l.Errorf("VerifyToken", err, "failed decode token")
		return claim, err
	}

	if err := claim.Valid(); err != nil {
		c.l.Errorf("VerifyToken", ErrInvalidToken, "validation failed")
		return claim, ErrInvalidToken
	}
	return claim, nil
}
