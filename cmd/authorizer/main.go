package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"github.com/golang-jwt/jwt"
)

const (
	checkHeader       = "Authorization"
	allowedValue      = "allow"
	resultHeader      = "x-ext-authz-check-result"
	receivedHeader    = "x-ext-authz-check-received"
	overrideHeader    = "x-ext-authz-additional-header-override"
	overrideGRPCValue = "grpc-additional-header-override-value"
	resultAllowed     = "allowed"
	resultDenied      = "denied"
)

var (
	serviceAccount = flag.String("allow_service_account", "a",
		"allowed service account, matched against the service account in the source principal from the client certificate")
	httpPort = flag.String("http", "8000", "HTTP server port")
	denyBody = fmt.Sprintf("denied by ext_authz for not found header `%s: %s` in the request", checkHeader, allowedValue)
	authz    = loadScopesFromDB()
)

// ExtAuthzServer implements the ext_authz v2/v3 gRPC and HTTP check request API.
type ExtAuthzServer struct {
	httpServer *http.Server
	// For test only
	httpPort chan int
}

// ServeHTTP implements the HTTP check request.
func (s *ExtAuthzServer) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		log.Printf("[HTTP] read body failed: %v", err)
	}
	l := fmt.Sprintf("%s %s%s, headers: %v, body: [%s]\n", request.Method, request.Host, request.URL, request.Header, body)
	headers := request.Header
	val, ok := headers["Authorization"]

	if !ok {
		denyRequest(request, response, l)
	} else {
		if len(val) == 0 {
			denyRequest(request, response, l)
		} else {
			jwtToken, parseValidation := parseJWTToken(val[0])
			if !parseValidation {
				denyRequest(request, response, l)
			} else {
				log.Println("------")
				log.Println(jwtToken)
				log.Println("------")
				claims := extractClaims(jwtToken)
				log.Println(claims)
				if len(claims) == 0 {
					denyRequest(request, response, l)
				} else {
					requestor := strings.ToLower(request.Method) + strings.ReplaceAll(request.URL.Path, "/", "::")
					log.Println(requestor)
					if checkClaim(requestor, claims) {
						allowRequest(request, response, l)
					} else {
						denyRequest(request, response, l)
					}
				}
			}
		}

	}
}

func denyRequest(request *http.Request, response http.ResponseWriter, l string) {
	response.Header().Set(resultHeader, resultDenied)
	response.Header().Set(overrideHeader, request.Header.Get(overrideHeader))
	response.Header().Set(receivedHeader, l)
	response.WriteHeader(http.StatusForbidden)
	_, _ = response.Write([]byte(denyBody))
}

func allowRequest(request *http.Request, response http.ResponseWriter, l string) {
	log.Printf("[HTTP][allowed]: %s", l)
	response.Header().Set(resultHeader, resultAllowed)
	response.Header().Set(overrideHeader, request.Header.Get(overrideHeader))
	response.Header().Set(receivedHeader, l)
	response.WriteHeader(http.StatusOK)
}

func checkClaim(requestor string, claims []interface{}) bool {
	log.Println("------")
	log.Println(requestor)
	log.Println(claims...)
	log.Println("------")
	for _, claim := range claims {
		rules := authz[claim.(string)]
		for _, rule := range rules {
			if requestor == rule {
				return true
			}
		}
	}
	return false
}

func loadScopesFromDB() map[string][]string {
	// Currently downloading from JSON as this is POC
	data := make(map[string][]string)
	jsonFile, err := os.Open("scope_to_rules.json")
	if err != nil {
		log.Println(err)
	}
	log.Println("Successfully Opened users.json")
	defer jsonFile.Close()

	byteValue, _ := ioutil.ReadAll(jsonFile)

	json.Unmarshal(byteValue, &data)
	return data
}

func extractClaims(tokenString string) []interface{} {
	var permissions []interface{}
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		fmt.Printf("Error %s", err)
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		// obtains claims
		permissions = claims["permissions"].([]interface{})
	}
	return permissions
}

func parseJWTToken(token string) (string, bool) {
	if token == "" {
		return "", false
	}
	jwtToken := strings.Split(token, "Bearer ")
	if len(jwtToken) == 1 {
		return jwtToken[0], true
	} else if len(jwtToken) == 2 {
		return jwtToken[1], true
	} else {
		return "", false
	}
}

func (s *ExtAuthzServer) startHTTP(address string, wg *sync.WaitGroup) {
	defer func() {
		wg.Done()
		log.Printf("Stopped HTTP server")
	}()

	listener, err := net.Listen("tcp", address)
	if err != nil {
		log.Fatalf("Failed to create HTTP server: %v", err)
	}
	// Store the port for test only.
	s.httpPort <- listener.Addr().(*net.TCPAddr).Port
	s.httpServer = &http.Server{Handler: s}

	log.Printf("Starting HTTP server at %s", listener.Addr())
	if err := s.httpServer.Serve(listener); err != nil {
		log.Fatalf("Failed to start HTTP server: %v", err)
	}
}

func (s *ExtAuthzServer) run(httpAddr string) {
	var wg sync.WaitGroup
	wg.Add(1)
	go s.startHTTP(httpAddr, &wg)
	wg.Wait()
}

func (s *ExtAuthzServer) stop() {
	log.Printf("HTTP server stopped: %v", s.httpServer.Close())
}

func NewExtAuthzServer() *ExtAuthzServer {
	return &ExtAuthzServer{
		httpPort: make(chan int, 1),
	}
}

func main() {
	flag.Parse()
	s := NewExtAuthzServer()
	go s.run(fmt.Sprintf(":%s", *httpPort))
	defer s.stop()

	// Wait for the process to be shutdown.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs
}
