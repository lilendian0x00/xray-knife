package web

import (
	"net/http"
)

// JWTMiddleware requires a valid Bearer token on protected API routes.
// Failures are 401 with a code the UI can act on (token_expired,
// token_revoked, unauthorized).
func (s *Server) JWTMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// If auth is not configured, just pass through.
		if !s.authEnabled() {
			next.ServeHTTP(w, r)
			return
		}

		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeJSONErrorCode(w, "Authorization header required", codeUnauthorized, http.StatusUnauthorized)
			return
		}

		tokenString, ok := bearerToken(authHeader)
		if !ok {
			writeJSONErrorCode(w, "Invalid token format", codeUnauthorized, http.StatusUnauthorized)
			return
		}

		if _, err := ValidateJWT(tokenString); err != nil {
			writeTokenError(w, err)
			return
		}

		next.ServeHTTP(w, r)
	})
}
