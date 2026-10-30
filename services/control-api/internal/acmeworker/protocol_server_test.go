package acmeworker

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type protocolOptions struct {
	badNonceCount      int
	rateLimitCount     int
	invalidAuth        bool
	pendingAuth        bool
	finalizeProcessing bool
	authzIdentifier    string
	// eabKeys requires External Account Binding with one of these HMAC
	// keys (by key ID).
	eabKeys map[string][]byte
	// omitAccountContact answers new-account without "contact", as Let's
	// Encrypt has since 2025-06 (it no longer stores or echoes contacts).
	omitAccountContact bool
	// foreignLeafKey issues the leaf for a key other than the CSR's, as when
	// the CA reused this pending order for another request that finalized it.
	foreignLeafKey bool
}

type protocolServer struct {
	t                  *testing.T
	server             *httptest.Server
	now                time.Time
	options            protocolOptions
	mu                 sync.Mutex
	nonces             map[string]bool
	nonceSequence      int
	accountPublic      crypto.PublicKey
	accountURI         string
	contacts           []string
	domains            []string
	authorizations     []protocolAuthorization
	orderCreated       bool
	finalized          bool
	chainPEM           []byte
	newOrderAttempts   int
	newAccountAttempts int
	postFinalizePolls  int
	rootKey            *ecdsa.PrivateKey
	rootCertificate    *x509.Certificate
	intermediateKey    *ecdsa.PrivateKey
	intermediateDER    []byte
}

type protocolAuthorization struct {
	identifier string
	wildcard   bool
	token      string
	status     string
}

func newProtocolServer(t *testing.T, now time.Time, options protocolOptions) *protocolServer {
	t.Helper()
	server := &protocolServer{t: t, now: now, options: options, nonces: make(map[string]bool)}
	server.makeCA()
	server.server = httptest.NewTLSServer(http.HandlerFunc(server.serveHTTP))
	t.Cleanup(server.server.Close)
	server.accountURI = server.url("/account/1")
	return server
}

func (s *protocolServer) url(path string) string { return s.server.URL + path }

func (s *protocolServer) serveHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method == http.MethodGet && request.URL.Path == "/directory" {
		s.addNonce(writer)
		directory := map[string]any{
			"newNonce":   s.url("/nonce"),
			"newAccount": s.url("/new-account"),
			"newOrder":   s.url("/new-order"),
		}
		if s.options.eabKeys != nil {
			directory["meta"] = map[string]any{"externalAccountRequired": true}
		}
		writeJSON(writer, http.StatusOK, directory)
		return
	}
	if request.URL.Path == "/nonce" && (request.Method == http.MethodHead || request.Method == http.MethodGet) {
		s.addNonce(writer)
		writer.WriteHeader(http.StatusOK)
		return
	}

	payload, protected, ok := s.verifyJWS(writer, request)
	if !ok {
		return
	}
	switch {
	case request.URL.Path == "/new-account":
		s.serveAccount(writer, payload, protected)
	case request.URL.Path == "/new-order":
		s.serveNewOrder(writer, payload)
	case request.URL.Path == "/order/1":
		s.serveOrder(writer)
	case strings.HasPrefix(request.URL.Path, "/authz/"):
		s.serveAuthorization(writer, request.URL.Path)
	case strings.HasPrefix(request.URL.Path, "/challenge/"):
		s.serveChallenge(writer, request.URL.Path)
	case request.URL.Path == "/finalize/1":
		s.serveFinalize(writer, payload)
	case request.URL.Path == "/certificate/1":
		s.addNonce(writer)
		writer.Header().Set("Content-Type", "application/pem-certificate-chain")
		writer.WriteHeader(http.StatusOK)
		_, _ = writer.Write(s.chainPEM)
	default:
		s.problem(writer, http.StatusNotFound, "malformed", "unknown endpoint")
	}
}

func (s *protocolServer) serveAccount(writer http.ResponseWriter, payload []byte, protected jwsProtected) {
	s.mu.Lock()
	s.newAccountAttempts++
	s.mu.Unlock()
	if protected.JWK == nil {
		s.problem(writer, http.StatusBadRequest, "malformed", "new account requires jwk")
		return
	}
	var request struct {
		Contact                []string `json:"contact"`
		OnlyReturnExisting     bool     `json:"onlyReturnExisting"`
		ExternalAccountBinding *struct {
			Protected string `json:"protected"`
			Payload   string `json:"payload"`
			Signature string `json:"signature"`
		} `json:"externalAccountBinding"`
	}
	if err := json.Unmarshal(payload, &request); err != nil {
		s.problem(writer, http.StatusBadRequest, "malformed", "invalid account")
		return
	}
	if s.options.eabKeys != nil && !request.OnlyReturnExisting {
		binding := request.ExternalAccountBinding
		if binding == nil {
			s.problem(writer, http.StatusUnauthorized, "externalAccountRequired", "external account binding required")
			return
		}
		rawProtected, err := base64.RawURLEncoding.DecodeString(binding.Protected)
		var header struct {
			Alg, Kid, URL string
		}
		if err != nil || json.Unmarshal(rawProtected, &header) != nil || header.Alg != "HS256" ||
			header.URL != s.url("/new-account") {
			s.problem(writer, http.StatusBadRequest, "malformed", "invalid external account binding")
			return
		}
		key, known := s.options.eabKeys[header.Kid]
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(binding.Protected + "." + binding.Payload))
		signature, _ := base64.RawURLEncoding.DecodeString(binding.Signature)
		boundKey, _ := base64.RawURLEncoding.DecodeString(binding.Payload)
		accountKey, _ := json.Marshal(protected.JWK)
		if !known || !hmac.Equal(mac.Sum(nil), signature) || !jsonEqual(boundKey, accountKey) {
			s.problem(writer, http.StatusUnauthorized, "unauthorized", "external account binding is invalid")
			return
		}
	}
	if request.OnlyReturnExisting && s.accountPublic == nil {
		s.problem(writer, http.StatusBadRequest, "accountDoesNotExist", "account absent")
		return
	}
	s.contacts = append([]string(nil), request.Contact...)
	s.addNonce(writer)
	writer.Header().Set("Location", s.accountURI)
	status := http.StatusCreated
	if request.OnlyReturnExisting {
		status = http.StatusOK
	}
	body := map[string]any{"status": "valid", "contact": s.contacts, "orders": s.url("/orders")}
	if s.options.omitAccountContact {
		delete(body, "contact")
	}
	writeJSON(writer, status, body)
}

func (s *protocolServer) serveNewOrder(writer http.ResponseWriter, payload []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.newOrderAttempts++
	if s.options.badNonceCount > 0 {
		s.options.badNonceCount--
		s.problemLocked(writer, http.StatusBadRequest, "badNonce", "nonce rejected")
		return
	}
	if s.options.rateLimitCount > 0 {
		s.options.rateLimitCount--
		writer.Header().Set("Retry-After", "0")
		s.problemLocked(writer, http.StatusTooManyRequests, "rateLimited", "try later")
		return
	}
	var request struct {
		Identifiers []struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"identifiers"`
	}
	if err := json.Unmarshal(payload, &request); err != nil || len(request.Identifiers) == 0 {
		s.problemLocked(writer, http.StatusBadRequest, "malformed", "invalid identifiers")
		return
	}
	s.domains = nil
	s.authorizations = nil
	for index, identifier := range request.Identifiers {
		wildcard := strings.HasPrefix(identifier.Value, "*.")
		name := strings.TrimPrefix(identifier.Value, "*.")
		s.domains = append(s.domains, identifier.Value)
		s.authorizations = append(s.authorizations, protocolAuthorization{
			identifier: name,
			wildcard:   wildcard,
			token:      fmt.Sprintf("token-%d", index),
			status:     "pending",
		})
	}
	s.orderCreated = true
	s.addNonceLocked(writer)
	writer.Header().Set("Location", s.url("/order/1"))
	writeJSON(writer, http.StatusCreated, s.orderBodyLocked("pending"))
}

func (s *protocolServer) serveOrder(writer http.ResponseWriter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	status := "pending"
	if s.finalized {
		if s.options.finalizeProcessing && s.postFinalizePolls == 0 {
			status = "processing"
			s.postFinalizePolls++
		} else {
			status = "valid"
		}
	} else if s.allAuthorizationsValidLocked() {
		status = "ready"
	}
	s.addNonceLocked(writer)
	writer.Header().Set("Location", s.url("/order/1"))
	writeJSON(writer, http.StatusOK, s.orderBodyLocked(status))
}

func (s *protocolServer) serveAuthorization(writer http.ResponseWriter, path string) {
	index := pathIndex(path)
	s.mu.Lock()
	defer s.mu.Unlock()
	if index < 0 || index >= len(s.authorizations) {
		s.problemLocked(writer, http.StatusNotFound, "malformed", "authorization absent")
		return
	}
	s.addNonceLocked(writer)
	writeJSON(writer, http.StatusOK, s.authorizationBodyLocked(index))
}

func (s *protocolServer) serveChallenge(writer http.ResponseWriter, path string) {
	index := pathIndex(path)
	s.mu.Lock()
	defer s.mu.Unlock()
	if index < 0 || index >= len(s.authorizations) {
		s.problemLocked(writer, http.StatusNotFound, "malformed", "challenge absent")
		return
	}
	if s.options.invalidAuth {
		s.authorizations[index].status = "invalid"
	} else if !s.options.pendingAuth {
		s.authorizations[index].status = "valid"
	}
	s.addNonceLocked(writer)
	writeJSON(writer, http.StatusOK, s.challengeBodyLocked(index))
}

func (s *protocolServer) serveFinalize(writer http.ResponseWriter, payload []byte) {
	var request struct {
		CSR string `json:"csr"`
	}
	if err := json.Unmarshal(payload, &request); err != nil {
		s.problem(writer, http.StatusBadRequest, "badCSR", "invalid finalize payload")
		return
	}
	csrDER, err := base64.RawURLEncoding.DecodeString(request.CSR)
	if err != nil {
		s.problem(writer, http.StatusBadRequest, "badCSR", "invalid csr encoding")
		return
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || csr.CheckSignature() != nil {
		s.problem(writer, http.StatusBadRequest, "badCSR", "invalid csr")
		return
	}
	s.chainPEM = s.issueChain(csr)
	s.mu.Lock()
	s.finalized = true
	s.addNonceLocked(writer)
	status := "valid"
	if s.options.finalizeProcessing {
		status = "processing"
	}
	body := s.orderBodyLocked(status)
	s.mu.Unlock()
	writeJSON(writer, http.StatusOK, body)
}

type jwsProtected struct {
	Algorithm string         `json:"alg"`
	Nonce     string         `json:"nonce"`
	URL       string         `json:"url"`
	KID       string         `json:"kid"`
	JWK       map[string]any `json:"jwk"`
}

func (s *protocolServer) verifyJWS(writer http.ResponseWriter, request *http.Request) ([]byte, jwsProtected, bool) {
	var envelope struct {
		Protected string `json:"protected"`
		Payload   string `json:"payload"`
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(request.Body).Decode(&envelope); err != nil {
		s.problem(writer, http.StatusBadRequest, "malformed", "invalid jws")
		return nil, jwsProtected{}, false
	}
	protectedJSON, err := base64.RawURLEncoding.DecodeString(envelope.Protected)
	if err != nil {
		s.problem(writer, http.StatusBadRequest, "malformed", "invalid protected header")
		return nil, jwsProtected{}, false
	}
	var protected jwsProtected
	if err := json.Unmarshal(protectedJSON, &protected); err != nil || protected.URL != s.url(request.URL.Path) {
		s.problem(writer, http.StatusBadRequest, "malformed", "protected url mismatch")
		return nil, jwsProtected{}, false
	}
	s.mu.Lock()
	validNonce := s.nonces[protected.Nonce]
	delete(s.nonces, protected.Nonce)
	s.mu.Unlock()
	if !validNonce {
		s.problem(writer, http.StatusBadRequest, "badNonce", "unknown nonce")
		return nil, jwsProtected{}, false
	}
	publicKey := s.accountPublic
	if protected.JWK != nil {
		publicKey, err = publicKeyFromJWK(protected.JWK)
		if err == nil && s.accountPublic == nil {
			s.accountPublic = publicKey
		}
	} else if protected.KID != s.accountURI {
		err = fmt.Errorf("kid mismatch")
	}
	if err != nil || publicKey == nil || !verifyJWSSignature(publicKey, envelope.Protected+"."+envelope.Payload, envelope.Signature) {
		s.problem(writer, http.StatusBadRequest, "malformed", "signature rejected")
		return nil, jwsProtected{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil {
		s.problem(writer, http.StatusBadRequest, "malformed", "payload rejected")
		return nil, jwsProtected{}, false
	}
	return payload, protected, true
}

func publicKeyFromJWK(jwk map[string]any) (crypto.PublicKey, error) {
	if jwk["kty"] != "EC" || jwk["crv"] != "P-256" {
		return nil, fmt.Errorf("unsupported jwk")
	}
	xEncoded, xOK := jwk["x"].(string)
	yEncoded, yOK := jwk["y"].(string)
	if !xOK || !yOK {
		return nil, fmt.Errorf("invalid jwk")
	}
	xBytes, xErr := base64.RawURLEncoding.DecodeString(xEncoded)
	yBytes, yErr := base64.RawURLEncoding.DecodeString(yEncoded)
	if xErr != nil || yErr != nil {
		return nil, fmt.Errorf("invalid jwk coordinates")
	}
	key := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xBytes), Y: new(big.Int).SetBytes(yBytes)}
	if !key.Curve.IsOnCurve(key.X, key.Y) {
		return nil, fmt.Errorf("jwk point is off curve")
	}
	return key, nil
}

func verifyJWSSignature(public crypto.PublicKey, signingInput, signature string) bool {
	ecdsaPublic, ok := public.(*ecdsa.PublicKey)
	if !ok {
		return false
	}
	bytes, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil || len(bytes) != 64 {
		return false
	}
	digest := sha256.Sum256([]byte(signingInput))
	return ecdsa.Verify(ecdsaPublic, digest[:], new(big.Int).SetBytes(bytes[:32]), new(big.Int).SetBytes(bytes[32:]))
}

func (s *protocolServer) orderBodyLocked(status string) map[string]any {
	identifiers := make([]map[string]string, len(s.domains))
	authzURLs := make([]string, len(s.authorizations))
	for index, domain := range s.domains {
		identifiers[index] = map[string]string{"type": "dns", "value": domain}
		authzURLs[index] = s.url(fmt.Sprintf("/authz/%d", index))
	}
	body := map[string]any{
		"status":         status,
		"identifiers":    identifiers,
		"authorizations": authzURLs,
		"finalize":       s.url("/finalize/1"),
	}
	if status == "valid" {
		body["certificate"] = s.url("/certificate/1")
	}
	return body
}

func (s *protocolServer) authorizationBodyLocked(index int) map[string]any {
	authorization := s.authorizations[index]
	identifier := authorization.identifier
	if index == 0 && s.options.authzIdentifier != "" {
		identifier = s.options.authzIdentifier
	}
	return map[string]any{
		"identifier": map[string]string{"type": "dns", "value": identifier},
		"status":     authorization.status,
		"wildcard":   authorization.wildcard,
		"challenges": []any{s.challengeBodyLocked(index, "http-01"), s.challengeBodyLocked(index, "dns-01")},
	}
}

func (s *protocolServer) challengeBodyLocked(index int, challengeTypes ...string) map[string]any {
	authorization := s.authorizations[index]
	challengeType := "http-01"
	if len(challengeTypes) > 0 {
		challengeType = challengeTypes[0]
	}
	body := map[string]any{
		"type":   challengeType,
		"url":    s.url(fmt.Sprintf("/challenge/%d", index)),
		"token":  authorization.token,
		"status": authorization.status,
	}
	if authorization.status == "invalid" {
		body["error"] = map[string]any{
			"type":   "urn:ietf:params:acme:error:unauthorized",
			"detail": "challenge response did not validate",
			"status": http.StatusForbidden,
		}
	}
	return body
}

func (s *protocolServer) allAuthorizationsValidLocked() bool {
	for _, authorization := range s.authorizations {
		if authorization.status != "valid" {
			return false
		}
	}
	return true
}

func (s *protocolServer) addNonce(writer http.ResponseWriter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addNonceLocked(writer)
}

func (s *protocolServer) addNonceLocked(writer http.ResponseWriter) {
	s.nonceSequence++
	nonce := fmt.Sprintf("nonce-%d", s.nonceSequence)
	s.nonces[nonce] = true
	writer.Header().Set("Replay-Nonce", nonce)
}

func (s *protocolServer) problem(writer http.ResponseWriter, status int, problemType, detail string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.problemLocked(writer, status, problemType, detail)
}

func (s *protocolServer) problemLocked(writer http.ResponseWriter, status int, problemType, detail string) {
	s.addNonceLocked(writer)
	writer.Header().Set("Content-Type", "application/problem+json")
	writeJSON(writer, status, map[string]any{
		"type":   "urn:ietf:params:acme:error:" + problemType,
		"detail": detail,
		"status": status,
	})
}

func (s *protocolServer) makeCA() {
	s.rootKey = mustKey(s.t)
	s.rootCertificate = &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ACME test root"},
		NotBefore:             s.now.Add(-time.Hour),
		NotAfter:              s.now.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, s.rootCertificate, s.rootCertificate, s.rootKey.Public(), s.rootKey)
	if err != nil {
		s.t.Fatal(err)
	}
	s.rootCertificate, err = x509.ParseCertificate(rootDER)
	if err != nil {
		s.t.Fatal(err)
	}
	s.intermediateKey = mustKey(s.t)
	intermediate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "ACME test intermediate"},
		NotBefore:             s.now.Add(-time.Hour),
		NotAfter:              s.now.Add(180 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	s.intermediateDER, err = x509.CreateCertificate(rand.Reader, intermediate, s.rootCertificate, s.intermediateKey.Public(), s.rootKey)
	if err != nil {
		s.t.Fatal(err)
	}
}

func (s *protocolServer) issueChain(csr *x509.CertificateRequest) []byte {
	intermediate, err := x509.ParseCertificate(s.intermediateDER)
	if err != nil {
		s.t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		DNSNames:     append([]string(nil), csr.DNSNames...),
		NotBefore:    s.now.Add(-time.Minute),
		NotAfter:     s.now.Add(90 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafPublic := csr.PublicKey
	if s.options.foreignLeafKey {
		leafPublic = mustKey(s.t).Public()
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, intermediate, leafPublic, s.intermediateKey)
	if err != nil {
		s.t.Fatal(err)
	}
	return append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: s.intermediateDER})...)
}

func pathIndex(path string) int {
	var index int
	if _, err := fmt.Sscanf(path[strings.LastIndex(path, "/"):], "/%d", &index); err != nil {
		return -1
	}
	return index
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// jsonEqual compares two JSON documents by value.
func jsonEqual(left, right []byte) bool {
	var a, b any
	if json.Unmarshal(left, &a) != nil || json.Unmarshal(right, &b) != nil {
		return false
	}
	ra, _ := json.Marshal(a)
	rb, _ := json.Marshal(b)
	return bytes.Equal(ra, rb)
}
