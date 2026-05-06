/*
FILE PATH: api/middleware/size_limit.go

Request body size enforcement via http.MaxBytesReader. HTTP 413 on exceed.
Applied before any parsing (earliest rejection point). Defense-in-depth:
submission.go also checks SDK-D11 after deserialization.
*/
package middleware

import "net/http"

// SizeLimit wraps the request body with http.MaxBytesReader.
// Exceeding maxBytes triggers automatic 413 on next Read.
func SizeLimit(maxBytes int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		next.ServeHTTP(w, r)
	})
}
