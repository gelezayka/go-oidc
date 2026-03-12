package goidc

import (
	"context"
)

// ClientManager gathers all the logic needed to manage clients.
type ClientManager interface {
	Save(ctx context.Context, client *Client) error
	Client(ctx context.Context, id string) (*Client, error)
	Delete(ctx context.Context, id string) error
}

type Client struct {
	ID     string `json:"client_id"`
	Secret string `json:"client_secret,omitempty" gorm:"column:client_secret"`
	// RegistrationToken is the plain text registration access token generated during
	// dynamic client registration.
	// Note: For security reasons, it is strongly recommended encrypt this value before storing it in a database.
	RegistrationToken  string `json:"registration_token,omitempty"`
	CreatedAtTimestamp int    `json:"created_at,omitempty" gorm:"column:created_at"`
	ExpiresAtTimestamp int    `json:"expires_at,omitempty" gorm:"column:expires_at"`

	FederationTrustAnchor string   `json:"federation_trust_anchor"`
	FederationTrustMarks  []string `json:"federation_trust_marks,omitempty" gorm:"type:json"`
	ProjectID     	      string   `json:"project_id" gorm:"column:project_id"`
	cachedJWKS            *JSONWebKeySet
	ClientMeta
}

func (c *Client) IsPublic() bool {
	return c.TokenAuthnMethod == AuthnMethodNone
}

func (c *Client) CachedJWKS() *JSONWebKeySet {
	return c.cachedJWKS
}

func (c *Client) CacheJWKS(jwks *JSONWebKeySet) {
	c.cachedJWKS = jwks
}

type ClientMeta struct {
	Name              string          `json:"client_name,omitempty" gorm:"column:client_name"`
	SecretExpiresAt   *int            `json:"client_secret_expires_at,omitempty" gorm:"column:client_secret_expires_at"`
	ApplicationType   ApplicationType `json:"application_type,omitempty"`
	LogoURI           string          `json:"logo_uri,omitempty" gorm:"column:logo_uri"`
	Contacts          []string        `json:"contacts,omitempty" gorm:"type:text;serializer:json"`
	PolicyURI         string          `json:"policy_uri,omitempty" gorm:"column:policy_uri"`
	TermsOfServiceURI string          `json:"tos_uri,omitempty" gorm:"column:tos_uri"`
	RedirectURIs      []string        `json:"redirect_uris,omitempty" gorm:"type:text;serializer:json"`
	RequestURIs       []string        `json:"request_uris,omitempty" gorm:"type:text;serializer:json"`
	GrantTypes        []GrantType     `json:"grant_types" gorm:"type:text;serializer:json"`
	ResponseTypes     []ResponseType  `json:"response_types" gorm:"type:text;serializer:json"`
	JWKSURI           string          `json:"jwks_uri,omitempty"`
	JWKS              *JSONWebKeySet  `json:"jwks,omitempty" gorm:"type:text;serializer:json"`
	SignedJWKSURI     string          `json:"signed_jwks_uri,omitempty"`
	// ScopeIDs contains the scopes available to the client separeted by spaces.
	ScopeIDs              string                     `json:"scope,omitempty" gorm:"column:scope"`
	SubIdentifierType     SubIdentifierType          `json:"subject_type,omitempty"`
	SectorIdentifierURI   string                     `json:"sector_identifier_uri,omitempty" gorm:"column:sector_identifier_uri"`
	IDTokenSigAlg         SignatureAlgorithm         `json:"id_token_signed_response_alg,omitempty" gorm:"column:id_token_signed_response_alg"`
	IDTokenKeyEncAlg      KeyEncryptionAlgorithm     `json:"id_token_encrypted_response_alg,omitempty" gorm:"column:id_token_encrypted_response_alg"`
	IDTokenContentEncAlg  ContentEncryptionAlgorithm `json:"id_token_encrypted_response_enc,omitempty" gorm:"column:id_token_encrypted_response_enc"`
	UserInfoSigAlg        SignatureAlgorithm         `json:"userinfo_signed_response_alg,omitempty" gorm:"column:userinfo_signed_response_alg"`
	UserInfoKeyEncAlg     KeyEncryptionAlgorithm     `json:"userinfo_encrypted_response_alg,omitempty" gorm:"column:userinfo_encrypted_response_alg"`
	UserInfoContentEncAlg ContentEncryptionAlgorithm `json:"userinfo_encrypted_response_enc,omitempty" gorm:"column:userinfo_encrypted_response_enc"`
	JARIsRequired         bool                       `json:"require_signed_request_object,omitempty" gorm:"column:require_signed_request_object"`
	// TODO: Is JAR required if this is informed?
	JARSigAlg                     SignatureAlgorithm         `json:"request_object_signing_alg,omitempty"`
	JARKeyEncAlg                  KeyEncryptionAlgorithm     `json:"request_object_encryption_alg,omitempty"`
	JARContentEncAlg              ContentEncryptionAlgorithm `json:"request_object_encryption_enc,omitempty"`
	JARMSigAlg                    SignatureAlgorithm         `json:"authorization_signed_response_alg,omitempty"`
	JARMKeyEncAlg                 KeyEncryptionAlgorithm     `json:"authorization_encrypted_response_alg,omitempty"`
	JARMContentEncAlg             ContentEncryptionAlgorithm `json:"authorization_encrypted_response_enc,omitempty"`
	TokenAuthnMethod              AuthnMethod                `json:"token_endpoint_auth_method" gorm:"column:token_endpoint_auth_method"`
	TokenAuthnSigAlg              SignatureAlgorithm         `json:"token_endpoint_auth_signing_alg,omitempty" gorm:"column:token_endpoint_auth_signing_alg"`
	TokenIntrospectionAuthnMethod AuthnMethod                `json:"introspection_endpoint_auth_method,omitempty"`
	TokenIntrospectionAuthnSigAlg SignatureAlgorithm         `json:"introspection_endpoint_auth_signing_alg,omitempty"`
	TokenRevocationAuthnMethod    AuthnMethod                `json:"revocation_endpoint_auth_method,omitempty"`
	TokenRevocationAuthnSigAlg    SignatureAlgorithm         `json:"revocation_endpoint_auth_signing_alg,omitempty"`
	DPoPTokenBindingIsRequired    bool                       `json:"dpop_bound_access_tokens,omitempty"`
	TLSSubDistinguishedName       string                     `json:"tls_client_auth_subject_dn,omitempty"`
	// TLSSubAlternativeName represents a DNS name.
	TLSSubAlternativeName     string                   `json:"tls_client_auth_san_dns,omitempty"`
	TLSSubAlternativeNameIp   string                   `json:"tls_client_auth_san_ip,omitempty"`
	TLSTokenBindingIsRequired bool                     `json:"tls_client_certificate_bound_access_tokens,omitempty"  gorm:"type:text;serializer:json"`
	AuthDetailTypes           []AuthDetailType         `json:"authorization_details_types,omitempty" gorm:"type:text;serializer:json"`
	DefaultMaxAgeSecs         *int                     `json:"default_max_age,omitempty"`
	DefaultACRValues          string                   `json:"default_acr_values,omitempty"`
	PARIsRequired             bool                     `json:"require_pushed_authorization_requests,omitempty"`
	CIBATokenDeliveryMode     CIBATokenDeliveryMode    `json:"backchannel_token_delivery_mode,omitempty"`
	CIBANotificationEndpoint  string                   `json:"backchannel_client_notification_endpoint,omitempty"`
	CIBAJARSigAlg             SignatureAlgorithm       `json:"backchannel_authentication_request_signing_alg,omitempty"`
	CIBAUserCodeIsEnabled     bool                     `json:"backchannel_user_code_parameter,omitempty"`
	OrganizationName          string                   `json:"organization_name,omitempty"`
	PostLogoutRedirectURIs    []string                 `json:"post_logout_redirect_uris,omitempty" gorm:"type:text;serializer:json"`
	ClientRegistrationTypes   []ClientRegistrationType `json:"client_registration_types,omitempty" gorm:"type:text;serializer:json"`
	DisplayName               string                   `json:"display_name,omitempty"`
	Description               string                   `json:"description,omitempty"`
	Keywords                  []string                 `json:"keywords,omitempty" gorm:"type:text;serializer:json"`
	InformationURI            string                   `json:"information_uri,omitempty"`
	OrganizationURI           string                   `json:"organization_uri,omitempty"`
	// CustomAttributes holds any additional dynamic attributes a client may
	// provide during registration.
	// These attributes allow clients to extend their metadata beyond the
	// predefined fields (e.g., client_name, logo_uri).
	// During DCR, any attributes that are not explicitly defined in the struct
	// will be captured here.
	// These additional fields are flattened in the DCR response, meaning
	// they are merged directly into the JSON response alongside standard fields.
	CustomAttributes map[string]any `json:"custom_attributes,omitempty" gorm:"type:text;serializer:json"`
	Claims []string `json:"claims,omitempty" gorm:"type:text;serializer:json"`
}

func (c *ClientMeta) SetCustomAttribute(key string, value any) {
	if c.CustomAttributes == nil {
		c.CustomAttributes = make(map[string]any)
	}
	c.CustomAttributes[key] = value
}

func (c *ClientMeta) CustomAttribute(key string) any {
	return c.CustomAttributes[key]
}
