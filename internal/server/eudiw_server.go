package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/kokukuma/mdoc-verifier/decoder"
	"github.com/kokukuma/mdoc-verifier/decoder/openid4vp"
	"github.com/kokukuma/mdoc-verifier/document"
	"github.com/kokukuma/mdoc-verifier/mdoc"
	"github.com/kokukuma/mdoc-verifier/session_transcript"
)

var (
	CredentialRequirementEUDIW = document.CredentialRequirement{
		CredentialType: document.CredentialTypeMDOC,
		Credentials: []document.Credential{
			{
				ID:        "mdl",
				DocType:   document.IsoMDL,
				Namespace: document.ISO1801351,
				ElementIdentifier: []mdoc.ElementIdentifier{
					document.IsoFamilyName,
					document.IsoGivenName,
					document.IsoBirthDate,
					document.IsoIssuingCountry,
				},
				Retention:       90,
				LimitDisclosure: "required",
			},
			{
				ID:        "eudi-pid",
				DocType:   document.EudiPid,
				Namespace: document.EUDIPID1,
				ElementIdentifier: []mdoc.ElementIdentifier{
					document.EudiFamilyName,
					document.EudiGivenName,
					document.EudiBirthDate,
					document.EudiIssuingCountry,
				},
				Retention:       90,
				LimitDisclosure: "required",
			},
		},
	}
)

func (s *Server) StartIdentityRequest(w http.ResponseWriter, r *http.Request) {
	session, err := s.sessions.NewSession("", &CredentialRequirementEUDIW)
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to SaveSession: %v", err), http.StatusBadRequest)
		return
	}

	// TODO: by valueの場合とby referenceの場合両方やってみるか？
	jar := openid4vp.JWTSecuredAuthorizeRequest{
		AuthorizeEndpoint: "eudi-openid4vp://verifier-backend.eudiw.dev",
		ClientID:          s.serverDomain,
		RequestURI:        fmt.Sprintf("https://%s/wallet/request.jwt/%s", s.serverDomain, session.ID), // request-id ?
	}

	jsonResponse(w, struct {
		URL string `json:"url"`
	}{
		URL: jar.String(),
	}, http.StatusOK)
}

func (s *Server) RequestJWT(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sessionID := vars["sessionid"]
	session, err := s.sessions.GetSession(sessionID)
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to GetSession: %v", err), http.StatusBadRequest)
		return
	}

	// create authorize request
	vpReq := openid4vp.AuthorizationRequest{
		ClientID:       s.serverDomain,
		ClientIDScheme: "x509_san_dns",
		ResponseType:   "vp_token",
		ResponseMode:   "direct_post.jwt",
		ResponseURI:    fmt.Sprintf("https://%s/wallet/direct_post", s.serverDomain),
		Nonce:          session.Nonce.String(),
		State:          sessionID,

		// TODO: presentation_definition_uri, client_metadata_uri使う形も試してみるか？
		//       まぁどっちでもいい。
		PresentationDefinition: CredentialRequirementEUDIW.PresentationDefinition(),
		// TODO: JwksURIは外から渡す形にしたほうがいい
		ClientMetadata: openid4vp.CreateClientMetadata(s.serverDomain),
	}

	// create RequestObject
	ro := openid4vp.RequestObject{
		AuthorizationRequest: vpReq,
		StandardClaims: jwt.StandardClaims{
			IssuedAt: time.Now().Unix(),
			Audience: "https://self-issued.me/v2",
		},
	}
	tokenString, err := ro.Sign(s.sigKey, s.certChain)
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to parse request: %v", err), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/oauth-authz-req+jwt")

	fmt.Fprintf(w, "%s", tokenString)
}

func (s *Server) JWKS(w http.ResponseWriter, r *http.Request) {
	jwks, err := ecdsaPublicKeyToJWKS(&s.encKey.PublicKey)
	if err != nil {
		panic(err)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

func (s *Server) DirectPost(w http.ResponseWriter, r *http.Request) {
	ar, err := decoder.ParseDirectPostJWT(r, s.encKey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	log.Printf("authorize request = %s", ar)

	session, err := s.sessions.GetSession(ar.State)
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to GetSession: %v", err), http.StatusBadRequest)
		return
	}

	// 1. get session_transcript
	sessTrans, err := session_transcript.OID4VPHandover([]byte(session.Nonce.String()), s.serverDomain, fmt.Sprintf("https://%s/wallet/direct_post", s.serverDomain), ar.APU)
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to get sessTrans: %v", err), http.StatusBadRequest)
		return
	}

	// 2. parse mdoc device response
	devResp, err := decoder.AuthzRespOpenID4VP(ar)
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to parse device responsee: %v", err), http.StatusBadRequest)
		return
	}

	// 3. verify mdoc device response
	var resp VerifyResponse
	for _, cred := range CredentialRequirementEUDIW.Credentials {
		doc, err := devResp.GetDocument(cred.DocType)
		if err != nil {
			fmt.Printf("document not found: %s", doc.DocType)
			continue
		}

		if err := mdoc.NewVerifier(
			roots,
			mdoc.WithSkipVerifyDeviceSigned(),
			// mdoc.WithSkipSignedDateValidation(),
			// mdoc.WithCertCurrentTime(date),
		).Verify(doc, sessTrans); err != nil {
			jsonErrorResponse(w, fmt.Errorf("failed to verify mdoc: %v", err), http.StatusBadRequest)
			return
		}

		for _, elemName := range cred.ElementIdentifier {
			elemValue, err := doc.GetElementValue(cred.Namespace, elemName)
			if err != nil {
				fmt.Printf("element not found: %s", elemName)
				continue
			}
			resp.Elements = append(resp.Elements, Element{
				NameSpace:  cred.Namespace,
				Identifier: elemName,
				Value:      elemValue,
			})
			log.Printf("element name=%s, value=%s", elemName, elemValue)
		}
	}

	s.sessions.AddVerifyResponse(ar.State, resp)

	jsonResponse(w, struct {
		RedirectURI string `json:"redirect_uri"`
	}{
		// TODO: the redirect_uri should be obtained at the start endpoint and save it on session.
		RedirectURI: fmt.Sprintf("https://%s?session_id=%s", s.clientDomain, ar.State),
	}, http.StatusOK)
}

type FinishIdentityRequest struct {
	SessionID string `json:"session_id"`
}

func (s *Server) FinishIdentityRequest(w http.ResponseWriter, r *http.Request) {
	req := FinishIdentityRequest{}
	if err := parseJSON(r, &req); err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to parse request: %v", err), http.StatusBadRequest)
		return
	}

	resp, err := s.sessions.GetVerifyResponse(req.SessionID) // transaction-id
	if err != nil {
		jsonErrorResponse(w, fmt.Errorf("failed to GetSession: %v", err), http.StatusBadRequest)
		return
	}

	jsonResponse(w, resp, http.StatusOK)
}
