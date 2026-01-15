package main

import (
	"errors"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	texttemplate "text/template"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/kokukuma/mdoc-verifier/internal/server"
)

func fileExists(p string) bool {
	if p == "" {
		return false
	}
	if st, err := os.Stat(p); err == nil && !st.IsDir() {
		return true
	}
	return false
}

func trimAllExt(name string) string {
	for {
		ext := filepath.Ext(name)
		if ext == "" {
			return name
		}
		name = name[:len(name)-len(ext)]
	}
}

func findTLSCertPair() (string, string, error) {
	baseDir, err := filepath.Abs(filepath.Dir("."))
	if err != nil {
		return "", "", err
	}
	certsDir := filepath.Join(baseDir, "certs")

	// Prefer specific domain certs
	specificCert := filepath.Join(certsDir, "digital-credentials.kgoro.click.pem")
	specificKey := filepath.Join(certsDir, "digital-credentials.kgoro.click-key.pem")
	if fileExists(specificCert) && fileExists(specificKey) {
		return specificCert, specificKey, nil
	}

	// Env override
	envCert := os.Getenv("TLS_CERT_FILE")
	envKey := os.Getenv("TLS_KEY_FILE")
	if fileExists(envCert) && fileExists(envKey) {
		return envCert, envKey, nil
	}

	type pair struct{ cert, key string }
	common := []pair{
		{filepath.Join(certsDir, "fullchain.pem"), filepath.Join(certsDir, "privkey.pem")},
		{filepath.Join(certsDir, "server.crt"), filepath.Join(certsDir, "server.key")},
		{filepath.Join(certsDir, "cert.pem"), filepath.Join(certsDir, "key.pem")},
	}
	for _, p := range common {
		if fileExists(p.cert) && fileExists(p.key) {
			return p.cert, p.key, nil
		}
	}

	// Fallback: scan directory
	entries, err := os.ReadDir(certsDir)
	if err == nil {
		var certCandidates []string
		var keyCandidates []string
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			ext := filepath.Ext(name)
			switch ext {
			case ".crt", ".pem":
				if filepath.Ext(name) == ".key" {
					break
				}
				certCandidates = append(certCandidates, filepath.Join(certsDir, name))
			case ".key":
				keyCandidates = append(keyCandidates, filepath.Join(certsDir, name))
			}
		}
		for _, c := range certCandidates {
			cb := trimAllExt(filepath.Base(c))
			for _, k := range keyCandidates {
				kb := trimAllExt(filepath.Base(k))
				if cb == kb {
					return c, k, nil
				}
			}
		}
		if len(certCandidates) > 0 && len(keyCandidates) > 0 {
			return certCandidates[0], keyCandidates[0], nil
		}
	}

	return "", "", errors.New("TLS certificate/key not found; set TLS_CERT_FILE and TLS_KEY_FILE or place certs under ./certs")
}

func main() {
	srv := server.NewServer()

	r := mux.NewRouter()
	r.Use(handlers.CORS(
		handlers.AllowedMethods([]string{"POST", "GET", "DELETE"}),
		handlers.AllowedHeaders([]string{"content-type"}),
		handlers.AllowedOrigins([]string{"*"}),
		handlers.AllowCredentials(),
	))

	// API routes (from cmd/server)
	r.HandleFunc("/getIdentityRequest", srv.GetIdentityRequest).Methods("POST", "OPTIONS")
	r.HandleFunc("/verifyIdentityResponse", srv.VerifyIdentityResponse).Methods("POST", "OPTIONS")

	// For EUDIW
	r.HandleFunc("/wallet/startIdentityRequest", srv.StartIdentityRequest).Methods("GET", "POST", "OPTIONS")
	r.HandleFunc("/wallet/request.jwt/{sessionid}", srv.RequestJWT).Methods("GET", "POST", "OPTIONS")
	r.HandleFunc("/wallet/jwks.json", srv.JWKS).Methods("GET", "POST", "OPTIONS")
	r.HandleFunc("/wallet/direct_post", srv.DirectPost).Methods("GET", "POST", "OPTIONS")
	r.HandleFunc("/wallet/finishIdentityRequest", srv.FinishIdentityRequest).Methods("GET", "POST", "OPTIONS")

	// 証明書管理API
	certRouter := r.PathPrefix("/api/certificates").Subrouter()
	certRouter.HandleFunc("", srv.ListCertificatesHandler).Methods("GET", "OPTIONS")
	certRouter.HandleFunc("/{filename}", srv.GetCertificateHandler).Methods("GET", "OPTIONS")
	certRouter.HandleFunc("", srv.AddCertificateHandler).Methods("POST", "OPTIONS")
	certRouter.HandleFunc("/json", srv.AddCertificateJSONHandler).Methods("POST", "OPTIONS")
	certRouter.HandleFunc("/{filename}", srv.DeleteCertificateHandler).Methods("DELETE", "OPTIONS")
	certRouter.HandleFunc("/reload", srv.ReloadCertificatesHandler).Methods("POST", "OPTIONS")

	// クライアント証明書チェーンAPI
	r.HandleFunc("/api/client-cert-chain", srv.GetClientCertChainHandler).Methods("GET", "OPTIONS")

	// Client routes (from cmd/client)
	jsTemplate := texttemplate.Must(texttemplate.ParseFiles(filepath.Join("cmd", "index.js")))
	r.HandleFunc("/index.js", func(w http.ResponseWriter, r *http.Request) {
		data := struct {
			ServerDomain string
		}{
			ServerDomain: os.Getenv("SERVER_DOMAIN"),
		}
		w.Header().Set("Content-Type", "application/javascript")
		if err := jsTemplate.Execute(w, data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	certJsTemplate := texttemplate.Must(texttemplate.ParseFiles(filepath.Join("cmd", "certificates.js")))
	r.HandleFunc("/certificates.js", func(w http.ResponseWriter, r *http.Request) {
		serverDomain := os.Getenv("SERVER_DOMAIN")
		if serverDomain == "" {
			serverDomain = "localhost:8080"
		}
		data := struct{ ServerAPIURL string }{
			ServerAPIURL: "https://" + serverDomain,
		}
		w.Header().Set("Content-Type", "application/javascript")
		if err := certJsTemplate.Execute(w, data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	templateJsTemplate := texttemplate.Must(texttemplate.ParseFiles(filepath.Join("cmd", "temprate.js")))
	r.HandleFunc("/temprate.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		if err := templateJsTemplate.Execute(w, nil); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	htmlTemplate := template.Must(template.ParseFiles(filepath.Join("cmd", "index.html")))
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		data := struct {
			ServerDomain string
		}{
			ServerDomain: os.Getenv("SERVER_DOMAIN"),
		}
		w.Header().Set("Content-Type", "text/html")
		if err := htmlTemplate.Execute(w, data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	certHtmlTemplate := template.Must(template.ParseFiles(filepath.Join("cmd", "certificates.html")))
	r.HandleFunc("/certificates.html", func(w http.ResponseWriter, r *http.Request) {
		data := struct {
			ServerDomain string
		}{
			ServerDomain: os.Getenv("SERVER_DOMAIN"),
		}
		w.Header().Set("Content-Type", "text/html")
		if err := certHtmlTemplate.Execute(w, data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	challenge := http.FileServer(http.Dir("./cmd/well-known/"))
	r.PathPrefix("/.well-known/").Handler(http.StripPrefix("/.well-known/", challenge))
	fs := http.FileServer(http.Dir("./cmd/"))
	r.PathPrefix("/").Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" ||
			r.URL.Path == "/index.js" ||
			r.URL.Path == "/temprate.js" ||
			r.URL.Path == "/certificates.js" ||
			r.URL.Path == "/certificates.html" {
			return
		}
		http.StripPrefix("/", fs).ServeHTTP(w, r)
	}))

	// Port configuration (shared)
	serverPort := os.Getenv("SERVER_PORT")
	if serverPort == "" {
		serverPort = os.Getenv("PORT")
	}
	if serverPort == "" {
		serverPort = ":443"
	}
	serverAddress := serverPort

	certFile, keyFile, err := findTLSCertPair()
	if err != nil {
		log.Fatalf("failed to locate TLS certificate/key: %v", err)
		return
	}
	log.Println("starting unified server (HTTPS) at", serverAddress)
	log.Printf("using TLS cert: %s, key: %s", certFile, keyFile)
	s := &http.Server{
		Addr:    serverAddress,
		Handler: r,
	}
	log.Fatal(s.ListenAndServeTLS(certFile, keyFile))
}
