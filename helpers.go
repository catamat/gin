package gin

import (
	"crypto/tls"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// Server defines the custom HTTP server struct.
type Server struct {
	Addr              string
	Handler           *Engine
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	MaxHeaderBytes    int
}

// NewServer creates a new custom HTTP server instance.
func NewServer(addr string, handler *Engine) *Server {
	server := &Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 30 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    0,
	}

	return server
}

// Run runs an HTTP server.
func (s *Server) Run() error {
	httpServer := &http.Server{
		Addr:    s.Addr,
		Handler: s.Handler,

		// The default server from net/http has no timeouts so we set some limits
		ReadHeaderTimeout: s.ReadHeaderTimeout,
		ReadTimeout:       s.ReadTimeout,
		WriteTimeout:      s.WriteTimeout,
		IdleTimeout:       s.IdleTimeout,
		MaxHeaderBytes:    s.MaxHeaderBytes,
	}

	return httpServer.ListenAndServe()
}

// RunTLS runs an HTTP server with tls cert/key files.
func (s *Server) RunTLS(cert, key string) error {
	httpServer := &http.Server{
		Addr:    s.Addr,
		Handler: s.Handler,

		// The default server from net/http has no timeouts so we set some limits
		ReadHeaderTimeout: s.ReadHeaderTimeout,
		ReadTimeout:       s.ReadTimeout,
		WriteTimeout:      s.WriteTimeout,
		IdleTimeout:       s.IdleTimeout,
		MaxHeaderBytes:    s.MaxHeaderBytes,

		TLSConfig: &tls.Config{
			// VersionTLS11 or VersionTLS12 would exclude many browsers
			// like Android 4.x, IE 10, Opera 12.17, Safari 6
			// So unfortunately not acceptable as a default yet
			MinVersion: tls.VersionTLS10,

			// Use default ciphersuite preferences, which are tuned to avoid attacks
			PreferServerCipherSuites: true,

			// Only use curves which have assembly implementations
			CurvePreferences: []tls.CurveID{
				tls.CurveP256,
				tls.X25519,
			},
		},
	}

	return httpServer.ListenAndServeTLS(cert, key)
}

// RunTLSAutocert runs an HTTPS server by requesting certs from an ACME provider.
// The server must be on a public IP which matches the DNS for the domains.
func (s *Server) RunTLSAutocert(email string, domains string) error {
	autocertDomains := strings.Split(domains, " ")

	certManager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Email:      email,                                      // Email for problems with certs
		HostPolicy: autocert.HostWhitelist(autocertDomains...), // Domains to request certs for
		Cache:      autocert.DirCache("secrets"),               // Cache certs in secrets folder
	}

	httpServer := &http.Server{
		Addr:    s.Addr,
		Handler: s.Handler,

		// The default server from net/http has no timeouts so we set some limits
		ReadHeaderTimeout: s.ReadHeaderTimeout,
		ReadTimeout:       s.ReadTimeout,
		WriteTimeout:      s.WriteTimeout,
		IdleTimeout:       s.IdleTimeout,
		MaxHeaderBytes:    s.MaxHeaderBytes,

		TLSConfig: &tls.Config{
			// Pass in a cert manager if you want one set
			// this will only be used if the server Certificates are empty
			GetCertificate: certManager.GetCertificate,

			// VersionTLS11 or VersionTLS12 would exclude many browsers
			// like Android 4.x, IE 10, Opera 12.17, Safari 6
			// So unfortunately not acceptable as a default yet
			MinVersion: tls.VersionTLS10,

			// Use default ciphersuite preferences, which are tuned to avoid attacks
			PreferServerCipherSuites: true,

			// Only use curves which have assembly implementations
			CurvePreferences: []tls.CurveID{
				tls.CurveP256,
				tls.X25519,
			},
		},
	}

	return httpServer.ListenAndServeTLS("", "")
}

// FormatResponse formats the server response specifing a message and its type.
func (c *Context) FormatResponse(typeOf string, message string) map[string]string {
	response := map[string]string{}
	response["typeOf"] = strings.TrimSpace(typeOf)
	response["message"] = strings.TrimSpace(message)
	return response
}

// Status200 responds with a status 200 (StatusOK).
func (c *Context) Status200() {
	c.Status(http.StatusOK)
}

// JSON200 responds with a JSON object and status 200 (StatusOK).
func (c *Context) JSON200(obj interface{}) {
	c.JSON(http.StatusOK, obj)
}

// Message200 responds with a formatted success message and status 200 (StatusOK).
func (c *Context) Message200(msg string) {
	c.JSON(http.StatusOK, c.FormatResponse("success", msg))
}

// Status400 responds with a status 400 (StatusBadRequest).
func (c *Context) Status400() {
	c.AbortWithStatus(http.StatusBadRequest)
}

// JSON400 responds with a JSON object and status 400 (StatusBadRequest).
func (c *Context) JSON400(obj interface{}) {
	c.AbortWithStatusJSON(http.StatusBadRequest, obj)
}

// Message400 responds with a formatted error message and status 400 (StatusBadRequest).
func (c *Context) Message400(msg string) {
	c.AbortWithStatusJSON(http.StatusBadRequest, c.FormatResponse("error", msg))
}

// Status401 responds with a status 401 (StatusUnauthorized).
func (c *Context) Status401() {
	c.AbortWithStatus(http.StatusUnauthorized)
}

// JSON401 responds with a JSON object and status 401 (StatusUnauthorized).
func (c *Context) JSON401(obj interface{}) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, obj)
}

// Message401 responds with a formatted error message and status 401 (StatusUnauthorized).
func (c *Context) Message401(msg string) {
	c.AbortWithStatusJSON(http.StatusUnauthorized, c.FormatResponse("error", msg))
}

// Status403 responds with a status 403 (StatusForbidden).
func (c *Context) Status403() {
	c.AbortWithStatus(http.StatusForbidden)
}

// JSON403 responds with a JSON object and status 403 (StatusForbidden).
func (c *Context) JSON403(obj interface{}) {
	c.AbortWithStatusJSON(http.StatusForbidden, obj)
}

// Message403 responds with a formatted error message and status 403 (StatusForbidden).
func (c *Context) Message403(msg string) {
	c.AbortWithStatusJSON(http.StatusForbidden, c.FormatResponse("error", msg))
}

// Status404 responds with a status 404 (StatusNotFound).
func (c *Context) Status404() {
	c.AbortWithStatus(http.StatusNotFound)
}

// JSON404 responds with a JSON object and status 404 (StatusNotFound).
func (c *Context) JSON404(obj interface{}) {
	c.AbortWithStatusJSON(http.StatusNotFound, obj)
}

// Message404 responds with a formatted error message and status 404 (StatusNotFound).
func (c *Context) Message404(msg string) {
	c.AbortWithStatusJSON(http.StatusNotFound, c.FormatResponse("error", msg))
}

// Status500 responds with a status 500 (StatusInternalServerError).
func (c *Context) Status500() {
	c.AbortWithStatus(http.StatusInternalServerError)
}

// JSON500 responds with a JSON object and status 500 (StatusInternalServerError).
func (c *Context) JSON500(obj interface{}) {
	c.AbortWithStatusJSON(http.StatusInternalServerError, obj)
}

// Message500 responds with a formatted error message and status 500 (StatusInternalServerError).
func (c *Context) Message500(msg string) {
	c.AbortWithStatusJSON(http.StatusInternalServerError, c.FormatResponse("error", msg))
}
