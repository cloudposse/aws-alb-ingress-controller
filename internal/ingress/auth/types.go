package auth

// authentication type
type Type string

const (
	TypeNone    Type = "none"
	TypeCognito Type = "cognito"
	TypeOIDC    Type = "oidc"
)

type OnUnauthenticatedRequest string

const (
	OnUnauthenticatedRequestAuthenticate OnUnauthenticatedRequest = "authenticate"
	OnUnauthenticatedRequestAllow        OnUnauthenticatedRequest = "allow"
	OnUnauthenticatedRequestDeny         OnUnauthenticatedRequest = "deny"
)

// configuration for IDP of Cognito
type IDPCognito struct {
	UserPoolArn      string
	UserPoolClientId string
	UserPoolDomain   string
}

// configuration for IDP of OIDC
type IDPOIDC struct {
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	UserInfoEndpoint      string
	ClientId              string
	ClientSecret          string
}

// authentication configuration
type Config struct {
	Type                     Type
	Scope                    string
	SessionCookie            string
	SessionTimeout           int64
	OnUnauthenticatedRequest OnUnauthenticatedRequest

	IDPCognito IDPCognito
	IDPOIDC    IDPOIDC
}

// the annotation schema for configuring IDPOIDC
// You can specify clientId & ClientSecret directly, or configure it as k8s secret
// The secret should be in same namespace as ingress/service and configured as "clientId: base64(ClientId) clientSecret: base64(ClientSecret)"
type AnnotationSchemaIDPOIDC struct {
	Issuer                string
	AuthorizationEndpoint string
	TokenEndpoint         string
	UserInfoEndpoint      string

	ClientId     string
	ClientSecret string

	SecretName string
}
