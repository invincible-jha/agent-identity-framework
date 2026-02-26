// SPDX-License-Identifier: BSL-1.1
// Copyright (c) 2026 MuVeraAI Corporation

package spiffe

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/aumos-ai/agent-identity-framework/types"
)

// X509SVID represents a parsed x509 SPIFFE Verifiable Identity Document.
type X509SVID struct {
	// SPIFFEID is the SPIFFE ID embedded in the certificate's SAN URI extension.
	SPIFFEID string
	// Certificate is the parsed x509 certificate.
	Certificate *x509.Certificate
	// TrustDomain is extracted from the SPIFFE ID.
	TrustDomain string
	// ExpiresAt is the certificate's NotAfter timestamp.
	ExpiresAt time.Time
	// SVIDType is always SVIDTypeX509 for this struct.
	SVIDType types.SVIDType
}

// JWTSVID represents a parsed JWT SPIFFE Verifiable Identity Document.
type JWTSVID struct {
	// SPIFFEID is the SPIFFE ID in the JWT's "sub" claim.
	SPIFFEID string
	// Audience is the intended audience of the JWT.
	Audience []string
	// ExpiresAt is parsed from the JWT's "exp" claim.
	ExpiresAt time.Time
	// IssuedAt is parsed from the JWT's "iat" claim.
	IssuedAt time.Time
	// SVIDType is always SVIDTypeJWT for this struct.
	SVIDType types.SVIDType
	// RawToken is the original JWT string (header.payload.signature).
	RawToken string
}

// SVIDHandler parses and validates x509 and JWT SVIDs.
// It does not perform cryptographic signature verification of JWT SVIDs;
// that requires the trust-domain's public key which must be supplied by the caller.
type SVIDHandler struct{}

// NewSVIDHandler constructs an SVIDHandler.
func NewSVIDHandler() *SVIDHandler {
	return &SVIDHandler{}
}

// ParseX509SVID parses a PEM-encoded x509 certificate and extracts the embedded SPIFFE ID.
// It validates that the certificate is not expired and contains exactly one SPIFFE ID.
func (h *SVIDHandler) ParseX509SVID(pemBytes []byte) (*X509SVID, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, &types.ErrSVIDInvalid{Reason: "no PEM block found"}
	}
	if block.Type != "CERTIFICATE" {
		return nil, &types.ErrSVIDInvalid{Reason: fmt.Sprintf("expected CERTIFICATE PEM block, got %s", block.Type)}
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, &types.ErrSVIDInvalid{Reason: fmt.Sprintf("parse x509 certificate: %v", err)}
	}

	// Extract SPIFFE ID from SAN URI extensions.
	spiffeID := ""
	for _, uri := range cert.URIs {
		if uri.Scheme == "spiffe" {
			if spiffeID != "" {
				return nil, &types.ErrSVIDInvalid{Reason: "certificate contains multiple SPIFFE IDs"}
			}
			spiffeID = uri.String()
		}
	}
	if spiffeID == "" {
		return nil, &types.ErrSVIDInvalid{Reason: "certificate contains no SPIFFE ID in SAN URI"}
	}

	trustDomain, _, err := ParseSPIFFEID(spiffeID)
	if err != nil {
		return nil, &types.ErrSVIDInvalid{Reason: fmt.Sprintf("invalid embedded SPIFFE ID: %v", err)}
	}

	if time.Now().UTC().After(cert.NotAfter) {
		return nil, &types.ErrSVIDInvalid{Reason: fmt.Sprintf("certificate expired at %s", cert.NotAfter.Format(time.RFC3339))}
	}

	return &X509SVID{
		SPIFFEID:    spiffeID,
		Certificate: cert,
		TrustDomain: trustDomain,
		ExpiresAt:   cert.NotAfter,
		SVIDType:    types.SVIDTypeX509,
	}, nil
}

// ValidateX509SVIDChain verifies that the leaf SVID is signed by one of the provided trusted roots.
func (h *SVIDHandler) ValidateX509SVIDChain(svid *X509SVID, trustedRoots []*x509.Certificate) error {
	if svid == nil {
		return &types.ErrSVIDInvalid{Reason: "nil SVID"}
	}

	rootPool := x509.NewCertPool()
	for _, root := range trustedRoots {
		rootPool.AddCert(root)
	}

	opts := x509.VerifyOptions{
		Roots:       rootPool,
		CurrentTime: time.Now().UTC(),
	}

	if _, err := svid.Certificate.Verify(opts); err != nil {
		return &types.ErrSVIDInvalid{Reason: fmt.Sprintf("certificate chain validation failed: %v", err)}
	}
	return nil
}

// ParseJWTSVID parses a JWT SVID token string without performing cryptographic
// signature verification. Callers must verify the signature using the trust-domain
// public key before trusting any claims.
func (h *SVIDHandler) ParseJWTSVID(token string) (*JWTSVID, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, &types.ErrSVIDInvalid{Reason: "JWT must have exactly 3 dot-separated segments"}
	}

	claims, err := decodeJWTPayload(parts[1])
	if err != nil {
		return nil, &types.ErrSVIDInvalid{Reason: fmt.Sprintf("decode JWT claims: %v", err)}
	}

	sub, _ := claims["sub"].(string)
	if sub == "" {
		return nil, &types.ErrSVIDInvalid{Reason: "JWT missing 'sub' claim"}
	}

	if _, _, err := ParseSPIFFEID(sub); err != nil {
		return nil, &types.ErrSVIDInvalid{Reason: fmt.Sprintf("'sub' is not a valid SPIFFE ID: %v", err)}
	}

	audience := extractAudience(claims)

	var expiresAt, issuedAt time.Time
	if exp, ok := claims["exp"].(float64); ok {
		expiresAt = time.Unix(int64(exp), 0).UTC()
	}
	if iat, ok := claims["iat"].(float64); ok {
		issuedAt = time.Unix(int64(iat), 0).UTC()
	}

	if !expiresAt.IsZero() && time.Now().UTC().After(expiresAt) {
		return nil, &types.ErrSVIDInvalid{Reason: fmt.Sprintf("JWT SVID expired at %s", expiresAt.Format(time.RFC3339))}
	}

	return &JWTSVID{
		SPIFFEID:  sub,
		Audience:  audience,
		ExpiresAt: expiresAt,
		IssuedAt:  issuedAt,
		SVIDType:  types.SVIDTypeJWT,
		RawToken:  token,
	}, nil
}

// SVIDPublicKey extracts the ECDSA public key from an x509 SVID certificate.
func (h *SVIDHandler) SVIDPublicKey(svid *X509SVID) (*ecdsa.PublicKey, error) {
	if svid == nil {
		return nil, &types.ErrSVIDInvalid{Reason: "nil SVID"}
	}
	ecKey, ok := svid.Certificate.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, &types.ErrSVIDInvalid{Reason: fmt.Sprintf("unsupported key type %T in SVID certificate", svid.Certificate.PublicKey)}
	}
	return ecKey, nil
}

// decodeJWTPayload base64url-decodes a JWT payload segment and JSON-unmarshals its claims.
func decodeJWTPayload(payload string) (map[string]interface{}, error) {
	// Add standard base64 padding if missing.
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}

	raw, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return nil, fmt.Errorf("base64url decode: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return nil, fmt.Errorf("unmarshal JWT payload: %w", err)
	}
	return claims, nil
}

// extractAudience normalises both single-string and array "aud" JWT claims.
func extractAudience(claims map[string]interface{}) []string {
	aud, ok := claims["aud"]
	if !ok {
		return nil
	}
	switch v := aud.(type) {
	case string:
		return []string{v}
	case []interface{}:
		result := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}
