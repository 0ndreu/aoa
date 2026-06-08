package aoa

// TokenType is an RFC 8693 par.3 token-type URI used for subject_token_type,
// actor_token_type, requested_token_type, and the response's issued_token_type.
type TokenType string

const (
	TokenTypeAccessToken  TokenType = "urn:ietf:params:oauth:token-type:access_token"
	TokenTypeRefreshToken TokenType = "urn:ietf:params:oauth:token-type:refresh_token"
	TokenTypeIDToken      TokenType = "urn:ietf:params:oauth:token-type:id_token"
	TokenTypeJWT          TokenType = "urn:ietf:params:oauth:token-type:jwt"
	TokenTypeSAML1        TokenType = "urn:ietf:params:oauth:token-type:saml1"
	TokenTypeSAML2        TokenType = "urn:ietf:params:oauth:token-type:saml2"
)

// orDefault returns the access-token type when t is empty.
func (t TokenType) orDefault() TokenType {
	if t == "" {
		return TokenTypeAccessToken
	}
	return t
}
