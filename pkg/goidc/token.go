package goidc

import (
	"context"

	"github.com/luikyv/go-oidc/internal/timeutil"
)

// TokenManager contains all the logic needed to manage access tokens.
type TokenManager interface {
	Save(context.Context, *Token) error
	TokenByID(context.Context, string) (*Token, error)
	Delete(context.Context, string) error
	// DeleteByGrantID deletes all tokens associated with the given grant
	// session ID. This is used for cascade revocation when a grant is revoked.
	DeleteByGrantID(context.Context, string) error
}

// Token represents an access token issued under a grant session.
// Each token has its own lifecycle and active fields snapshotted at issuance.
type Token struct {
	ID                   string                `json:"id" gorm:"column:id"`
	GrantID              string                `json:"grant_id" gorm:"column:grant_id"`
	ClientID             string                `json:"client_id" gorm:"column:client_id"`
	Subject              string                `json:"sub" gorm:"column:sub"`
	CreatedAtTimestamp   int                   `json:"created_at" gorm:"column:created_at"`
	ExpiresAtTimestamp   int                   `json:"expires_at" gorm:"column:expires_at"`
	Format               TokenFormat           `json:"format" gorm:"column:format"`
	Type                 TokenType             `json:"type"`
	SigAlg               SignatureAlgorithm    `json:"signature_algorithm,omitempty" gorm:"column:signature_algorithm"`
	Scopes               string                `json:"scopes"`
	AuthDetails          []AuthorizationDetail `json:"auth_details,omitempty" gorm:"column:auth_details;type:text;serializer:json"`
	Resources            Resources             `json:"resources,omitempty" gorm:"column:auth_details;type:text;serializer:json"`
	JWKThumbprint        string                `json:"jwk_thumbprint,omitempty" gorm:"column:jwk_thumbprint"`
	ClientCertThumbprint string                `json:"client_cert_thumbprint,omitempty" gorm:"column:client_cert_thumbprint"`
}

// LifetimeSecs returns the token's total lifetime in seconds.
func (t *Token) LifetimeSecs() int {
	return t.ExpiresAtTimestamp - t.CreatedAtTimestamp
}

// IsExpired returns whether the token has expired.
func (t *Token) IsExpired() bool {
	return timeutil.TimestampNow() >= t.ExpiresAtTimestamp
}
