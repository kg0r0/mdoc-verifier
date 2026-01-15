package server

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/fxamacker/cbor/v2"
	"github.com/kokukuma/mdoc-verifier/decoder"
	"github.com/kokukuma/mdoc-verifier/decoder/openid4vp"
	"github.com/kokukuma/mdoc-verifier/document"
	"github.com/kokukuma/mdoc-verifier/mdoc"
	"github.com/kokukuma/mdoc-verifier/session_transcript"
)

type IdentityRequest struct {
	Selector        document.Selector `json:"selector"`
	Nonce           string            `json:"nonce"`
	ReaderPublicKey string            `json:"readerPublicKey"`
}

type VwWOnTheWebRequest struct {
	DevivceRequest string `json:"deviceRequest"`
	EncryptionInfo string `json:"encryptionInfo"`
}

type EncryptionParameters struct {
	Nonce              []byte `json:"nonce"`
	RecipientPublicKey []byte `json:"recipientPublicKey"`
}

type DeviceRequest struct {
	Version       string       `json:"version"`
	DocRequests   []DocRequest `json:"docRequests"`
	ReaderAuthAll []ReaderAuth `json:"readerAuthAll"`
}

type DocRequest struct {
	itemsRequest []interface{}
}

type ReaderAuth []interface{}

func createIDReq(req GetRequest, session *Session) interface{} {
	var idReq interface{}
	switch req.Protocol {
	case "org-iso-mdoc":
		// TODO: handle error properly
		base64EncryptionInfo, _ := generateBase64EncryptionInfo(session.GetNonceByte(), session.PrivateKey.PublicKey().Bytes())
		deviceRequest, _ := BuildDeviceRequest()
		idReq = &VwWOnTheWebRequest{
			DevivceRequest: deviceRequest,
			EncryptionInfo: base64EncryptionInfo,
		}
	case "preview":
		// MEMO: Unclear if preview will survive.
		// Ege's blog only mentioned openid4vp, and I think it's going to disappear.
		idReq = &IdentityRequest{
			Selector:        session.CredentialRequirement.Selector()[0], // Identity Credential API only accept single selector ... ?
			Nonce:           session.Nonce.String(),
			ReaderPublicKey: b64.EncodeToString(session.PrivateKey.PublicKey().Bytes()),
		}
	case "openid4vp":
		idReq = &openid4vp.AuthorizationRequest{
			ClientID:               "digital-credentials.dev",
			ClientIDScheme:         "web-origin",
			ResponseType:           "vp_token",
			Nonce:                  session.Nonce.String(),
			PresentationDefinition: session.CredentialRequirement.PresentationDefinition(),
			// DCQLQuery:              session.CredentialRequirement.DCQLQuery(),
		}
	case "apple":
		// MEMO: Apple is practically only Nonce so I wouldn't say they care that much.
		idReq = &IdentityRequest{
			Nonce: session.Nonce.String(),
		}
	}
	return idReq
}

func getSessionTranscript(req VerifyRequest, session *Session) ([]byte, error) {
	var sessTrans []byte
	var err error

	switch req.Protocol {
	case "openid4vp":
		hash := sha256.Sum256([]byte("digital-credentials.dev"))

		// The request came from native app.
		sessTrans, err = session_transcript.AndroidHandoverV1(session.GetNonceByte(), "com.android.mdl.appreader", hash[:])

		// The request came from browser app.
		if req.Origin != "" {
			sessTrans, err = session_transcript.BrowserHandoverV1(session.GetNonceByte(), req.Origin, hash[:])
		}
	case "preview":
		// The request came from native app.
		sessTrans, err = session_transcript.AndroidHandoverV1(session.GetNonceByte(), "com.android.mdl.appreader", session.GetPublicKeyHash())

		// The request came from browser app.
		if req.Origin != "" {
			sessTrans, err = session_transcript.BrowserHandoverV1(session.GetNonceByte(), req.Origin, session.GetPublicKeyHash())
		}
	case "apple":
		// The request came from iOS app.
		sessTrans, err = session_transcript.AppleHandoverV1(merchantID, teamID, session.GetNonceByte(), session.GetPublicKeyHash())
	}
	if err != nil {
		return nil, err
	}
	return sessTrans, nil
}

func parseDeviceResponse(req VerifyRequest, session *Session, sessTrans []byte) (*mdoc.DeviceResponse, error) {
	var devResp *mdoc.DeviceResponse
	var err error

	switch req.Protocol {
	case "openid4vp":
		devResp, err = decoder.OpenID4VP(req.Data)
	case "preview":
		devResp, err = decoder.AndroidHPKE(req.Data, session.GetPrivateKey(), sessTrans)
	case "apple":
		// This base64URL encoding is not in any spec, just depends on a client implementation.
		decoded, err := b64.DecodeString(req.Data)
		if err != nil {
			return nil, err
		}
		devResp, err = decoder.AppleHPKE(decoded, session.GetPrivateKey(), sessTrans)
	}
	if err != nil {
		return nil, err
	}
	return devResp, nil
}

func verifierOptionsForDevelopment(protocol string) []mdoc.VerifierOption {
	var verifierOptions []mdoc.VerifierOption

	switch protocol {
	case "openid4vp", "preview":
		verifierOptions = []mdoc.VerifierOption{
			// mdoc.WithSkipSignedDateValidation(),
			// mdoc.WithSkipVerifyCertificate(),
		}
	case "apple":
		verifierOptions = []mdoc.VerifierOption{
			mdoc.WithSkipVerifyDeviceSigned(),
			mdoc.WithSkipVerifyCertificate(),
			mdoc.WithSkipVerifyIssuerAuth(),
		}
	}
	return verifierOptions
}

func getVerifiedDoc(devResp *mdoc.DeviceResponse, docType mdoc.DocType, sessTrans []byte, protocol string, certPool *x509.CertPool) (*mdoc.Document, error) {
	doc, err := devResp.GetDocument(docType)
	if err != nil {
		return nil, err
	}
	options := verifierOptionsForDevelopment(protocol)

	// set verifier options mainly because there is no legitimate wallet for now.
	if err := mdoc.NewVerifier(certPool, options...).Verify(doc, sessTrans); err != nil {
		return nil, err
	}
	return doc, nil
}

func generateBase64EncryptionInfo(nonce []byte, recipientPublicKey []byte) (string, error) {
	encryptionParameters := EncryptionParameters{
		Nonce:              nonce,
		RecipientPublicKey: recipientPublicKey,
	}
	encryptionInfo := []interface{}{
		"dcapi",
		encryptionParameters,
	}
	encryptionInfoBytes, err := cbor.Marshal(encryptionInfo)
	if err != nil {
		return "", fmt.Errorf("failed to encode encryption info: %w", err)
	}
	base64EncryptionInfo := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(encryptionInfoBytes)
	return base64EncryptionInfo, nil
}

// loadCertDER reads a PEM-encoded certificate and returns its DER bytes.
func loadCertDER(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM certificate")
	}
	return block.Bytes, nil
}

// loadECDSAPrivateKey reads a PEM-encoded private key and returns an ECDSA private key.
// Supports both EC PRIVATE KEY (SEC1) and PKCS#8 formats.
func loadECDSAPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM private key")
	}
	// Try PKCS#8 first
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if pk, ok := key.(*ecdsa.PrivateKey); ok {
			return pk, nil
		}
		return nil, fmt.Errorf("private key is not ECDSA")
	}
	// Fallback to EC private key (SEC1)
	pk, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EC private key: %w", err)
	}
	return pk, nil
}

// signReaderAuth constructs the COSE Sig_structure for Sign1 and returns a raw (r||s) 64-byte signature.
// Sig_structure: ["Signature1", protected, external_aad, payload]
// - protected: serialized protected header bytes (bstr)
// - external_aad: empty bstr
// - payload: CBOR-encoded itemsRequest payload bytes
func signReaderAuth(priv *ecdsa.PrivateKey, protected []byte, payload []byte) ([]byte, error) {
	sigStructure := []interface{}{
		"Signature1",
		cbor.RawMessage(protected),
		[]byte{},
		payload,
	}
	toSign, err := cbor.Marshal(sigStructure)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Sig_structure: %w", err)
	}
	hash := sha256.Sum256(toSign)
	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign Sig_structure: %w", err)
	}
	// Convert r,s to fixed 32-byte big-endian and concatenate (COSE requires raw R||S)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	sig := make([]byte, 64)
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)
	return sig, nil
}

// buildDeviceRequestMap returns a Go representation of the following CBOR-decoded structure:
//
//	{
//	  "version": "1.1",
//	  "docRequests": [
//	    {
//	      "itemsRequest": 24(<< { ... } >>)
//	    }
//	  ],
//	  "readerAuthAll": [
//	    [
//	      h'a10126',
//	      { 33: h'...' },
//	      null,
//	      h'...'
//	    ]
//	  ],
//	  "deviceRequestInfo": 24(<< { ... } >>)
//	}
func buildDeviceRequestMap() (map[string]interface{}, error) {
	// itemsRequest payload (tag 24)
	itemsRequestInner := map[string]interface{}{
		"docType": "org.iso.18013.5.1.mDL",
		"nameSpaces": map[string]interface{}{
			"org.iso.18013.5.1": map[string]bool{
				"portrait":    true,
				"given_name":  true,
				"age_over_21": false,
				"family_name": true,
			},
		},
	}

	// CBOR-encoded payload bytes for reader authentication signature (detached payload)
	itemsRequestPayload, err := cbor.Marshal(itemsRequestInner)
	if err != nil {
		return nil, fmt.Errorf("failed to CBOR-encode itemsRequest payload: %w", err)
	}
	// Convert to hex and decode back to bytes for tag 24 content
	itemsRequestHex := hex.EncodeToString(itemsRequestPayload)
	itemsRequestBytes, err := hex.DecodeString(itemsRequestHex)
	if err != nil {
		return nil, fmt.Errorf("failed to hex-decode itemsRequest payload: %w", err)
	}

	// readerAuthAll COSE_Sign1 structure
	protectedHex := "a10126" // << {1: -7} >>
	protected, err := hex.DecodeString(protectedHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode protected header: %w", err)
	}

	// Load certificate DER from certs/apple.cert and hex-encode it (for parity with previous logic)
	certDER, err := loadCertDER("certs/apple.cert")
	if err != nil {
		return nil, err
	}
	certHex := hex.EncodeToString(certDER)
	cert, _ := hex.DecodeString(certHex)

	// Load ECDSA private key and generate signature over Sig_structure with detached payload
	priv, err := loadECDSAPrivateKey("certs/apple.key")
	if err != nil {
		return nil, err
	}
	sigBytes, err := signReaderAuth(priv, protected, itemsRequestPayload)
	if err != nil {
		return nil, err
	}
	signatureHex := hex.EncodeToString(sigBytes)
	signature, _ := hex.DecodeString(signatureHex)

	readerAuth := []interface{}{
		protected,
		map[int]interface{}{
			33: cert,
		},
		nil,
		signature,
	}

	// deviceRequestInfo payload (tag 24)
	deviceRequestInfoInner := map[string]interface{}{
		"useCases": []interface{}{
			map[string]interface{}{
				"mandatory": true,
				"documentSets": []interface{}{
					[]interface{}{0},
				},
			},
		},
	}
	// Encode, hex, and decode for tag 24 content
	deviceRequestInfoPayload, err := cbor.Marshal(deviceRequestInfoInner)
	if err != nil {
		return nil, fmt.Errorf("failed to CBOR-encode deviceRequestInfo payload: %w", err)
	}
	deviceRequestInfoHex := hex.EncodeToString(deviceRequestInfoPayload)
	deviceRequestInfoBytes, err := hex.DecodeString(deviceRequestInfoHex)
	if err != nil {
		return nil, fmt.Errorf("failed to hex-decode deviceRequestInfo payload: %w", err)
	}

	out := map[string]interface{}{
		"version": "1.1",
		"docRequests": []interface{}{
			map[string]interface{}{
				"itemsRequest": cbor.Tag{Number: 24, Content: itemsRequestBytes},
			},
		},
		"readerAuthAll": []interface{}{
			readerAuth,
		},
		"deviceRequestInfo": cbor.Tag{Number: 24, Content: deviceRequestInfoBytes},
	}
	return out, nil
}

// BuildDeviceRequest returns the device request CBOR encoded and then base64url (no padding) encoded.
func BuildDeviceRequest() (string, error) {
	m, err := buildDeviceRequestMap()
	if err != nil {
		return "", err
	}
	data, err := cbor.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("failed to CBOR-encode device request: %w", err)
	}
	enc := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(data)
	return enc, nil
}

// BuildDeviceRequestExampleCBOR returns the device request encoded as CBOR bytes (for tests).
func BuildDeviceRequestExampleCBOR() ([]byte, error) {
	m, err := buildDeviceRequestMap()
	if err != nil {
		return nil, err
	}
	return cbor.Marshal(m)
}
