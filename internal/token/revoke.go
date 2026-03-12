package token

import (
	"github.com/gelezayka/go-oidc/internal/client"
	"github.com/gelezayka/go-oidc/internal/oidc"
	"github.com/gelezayka/go-oidc/pkg/goidc"
)

func revoke(ctx oidc.Context, req queryRequest) error {
	c, err := client.Authenticated(ctx, client.AuthnContextTokenRevocation)
	if err != nil {
		return err
	}

	if !ctx.IsClientAllowedTokenRevocation(c) {
		return goidc.NewError(goidc.ErrorCodeAccessDenied, "client not allowed to revoke tokens")
	}

	info, err := IntrospectionInfo(ctx, req.token)
	// If the token was not found, is expired, etc., there's no point in revoking it.
	if err != nil || !info.IsActive {
		return nil
	}

	if c.ID != info.ClientID {
		return goidc.NewError(goidc.ErrorCodeAccessDenied, "token was not issued for this client")
	}

	_ = ctx.DeleteGrant(info.GrantID)
	_ = ctx.DeleteTokensByGrantID(info.GrantID)
	return nil
}
