package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	stdlog "log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/armon/go-proxyproto"
	"github.com/containous/mux"
	"github.com/containous/traefik/cluster"
	"github.com/containous/traefik/configuration"
	"github.com/containous/traefik/h2c"
	"github.com/containous/traefik/log"
	"github.com/containous/traefik/metrics"
	"github.com/containous/traefik/middlewares"
	"github.com/containous/traefik/middlewares/accesslog"
	"github.com/containous/traefik/middlewares/tracing"
	"github.com/containous/traefik/provider"
	"github.com/containous/traefik/safe"
	traefiktls "github.com/containous/traefik/tls"
	"github.com/containous/traefik/types"
	"github.com/containous/traefik/whitelist"
	"github.com/sirupsen/logrus"
	"github.com/urfave/negroni"
	"github.com/xenolf/lego/acme"
)

var httpServerLogger = stdlog.New(log.WriterLevel(logrus.DebugLevel), "", 0)

func newHijackConnectionTracker() *hijackConnectionTracker {
	return &hijackConnectionTracker{
		conns: make(map[net.Conn]struct{}),
	}
}

type hijackConnectionTracker struct {
	conns map[net.Conn]struct{}
	lock  sync.RWMutex
}

// AddHijackedConnection add a connection in the tracked connections list
func (h *hijackConnectionTracker) AddHijackedConnection(conn net.Conn) {
	h.lock.Lock()
	defer h.lock.Unlock()
	h.conns[conn] = struct{}{}
}

// RemoveHijackedConnection remove a connection from the tracked connections list
func (h *hijackConnectionTracker) RemoveHijackedConnection(conn net.Conn) {
	h.lock.Lock()
	defer h.lock.Unlock()
	delete(h.conns, conn)
}

// Shutdown wait for the connection closing
func (h *hijackConnectionTracker) Shutdown(ctx context.Context) error {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		h.lock.RLock()
		if len(h.conns) == 0 {
			return nil
		}
		h.lock.RUnlock()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// Close close all the connections in the tracked connections list
func (h *hijackConnectionTracker) Close() {
	for conn := range h.conns {
		if err := conn.Close(); err != nil {
			log.Errorf("Error while closing Hijacked conn: %v", err)
		}
		delete(h.conns, conn)
	}
}

// Server is the reverse-proxy/load-balancer engine
type Server struct {
	serverEntryPoints             serverEntryPoints
	configurationChan             chan types.ConfigMessage
	configurationValidatedChan    chan types.ConfigMessage
	signals                       chan os.Signal
	stopChan                      chan bool
	currentConfigurations         safe.Safe
	providerConfigUpdateMap       map[string]chan types.ConfigMessage
	globalConfiguration           configuration.GlobalConfiguration
	accessLoggerMiddleware        *accesslog.LogHandler
	tracingMiddleware             *tracing.Tracing
	routinesPool                  *safe.Pool
	leadership                    *cluster.Leadership
	defaultForwardingRoundTripper http.RoundTripper
	metricsRegistry               metrics.Registry
	provider                      provider.Provider
	configurationListeners        []func(types.Configuration)
	entryPoints                   map[string]EntryPoint
	bufferPool                    httputil.BufferPool
}

// EntryPoint entryPoint information (configuration + internalRouter)
type EntryPoint struct {
	InternalRouter   types.InternalRouter
	Configuration    *configuration.EntryPoint
	OnDemandListener func(string) (*tls.Certificate, error)
	TLSALPNGetter    func(string) (*tls.Certificate, error)
	CertificateStore *traefiktls.CertificateStore
}

type serverEntryPoints map[string]*serverEntryPoint

type serverEntryPoint struct {
	httpServer              *h2c.Server
	listener                net.Listener
	httpRouter              *middlewares.HandlerSwitcher
	certs                   *traefiktls.CertificateStore
	onDemandListener        func(string) (*tls.Certificate, error)
	tlsALPNGetter           func(string) (*tls.Certificate, error)
	hijackConnectionTracker *hijackConnectionTracker
}

func (s serverEntryPoint) Shutdown(ctx context.Context) {
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.httpServer.Shutdown(ctx); err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				log.Debugf("Wait server shutdown is over due to: %s", err)
				err = s.httpServer.Close()
				if err != nil {
					log.Error(err)
				}
			}
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.hijackConnectionTracker.Shutdown(ctx); err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				log.Debugf("Wait hijack connection is over due to: %s", err)
				s.hijackConnectionTracker.Close()
			}
		}
	}()
	wg.Wait()
}

// NewServer returns an initialized Server.
func NewServer(globalConfiguration configuration.GlobalConfiguration, provider provider.Provider, entrypoints map[string]EntryPoint) *Server {
	server := &Server{}

	server.entryPoints = entrypoints
	server.provider = provider
	server.globalConfiguration = globalConfiguration
	server.serverEntryPoints = make(map[string]*serverEntryPoint)
	server.configurationChan = make(chan types.ConfigMessage, 100)
	server.configurationValidatedChan = make(chan types.ConfigMessage, 100)
	server.signals = make(chan os.Signal, 1)
	server.stopChan = make(chan bool, 1)
	server.configureSignals()
	currentConfigurations := make(types.Configurations)
	server.currentConfigurations.Set(currentConfigurations)
	server.providerConfigUpdateMap = make(map[string]chan types.ConfigMessage)

	if server.globalConfiguration.API != nil {
		server.globalConfiguration.API.CurrentConfigurations = &server.currentConfigurations
	}

	server.bufferPool = newBufferPool()

	server.routinesPool = safe.NewPool(context.Background())

	transport, err := createHTTPTransport(globalConfiguration)
	if err != nil {
		log.Errorf("failed to create HTTP transport: %v", err)
	}

	server.defaultForwardingRoundTripper = transport

	server.tracingMiddleware = globalConfiguration.Tracing
	if server.tracingMiddleware != nil && server.tracingMiddleware.Backend != "" {
		server.tracingMiddleware.Setup()
	}

	server.metricsRegistry = registerMetricClients(globalConfiguration.Metrics)

	if globalConfiguration.Cluster != nil {
		// leadership creation if cluster mode
		server.leadership = cluster.NewLeadership(server.routinesPool.Ctx(), globalConfiguration.Cluster)
	}

	if globalConfiguration.AccessLog != nil {
		var err error
		server.accessLoggerMiddleware, err = accesslog.NewLogHandler(globalConfiguration.AccessLog)
		if err != nil {
			log.Warnf("Unable to create log handler: %s", err)
		}
	}
	return server
}

// Start starts the server.
func (s *Server) Start() {
	s.startHTTPServers()
	s.startLeadership()
	s.routinesPool.Go(func(stop chan bool) {
		s.listenProviders(stop)
	})
	s.routinesPool.Go(func(stop chan bool) {
		s.listenConfigurations(stop)
	})
	s.startProvider()
	go s.listenSignals()
}

// StartWithContext starts the server and Stop/Close it when context is Done
func (s *Server) StartWithContext(ctx context.Context) {
	go func() {
		defer s.Close()
		<-ctx.Done()
		log.Info("I have to go...")
		reqAcceptGraceTimeOut := time.Duration(s.globalConfiguration.LifeCycle.RequestAcceptGraceTimeout)
		if reqAcceptGraceTimeOut > 0 {
			log.Infof("Waiting %s for incoming requests to cease", reqAcceptGraceTimeOut)
			time.Sleep(reqAcceptGraceTimeOut)
		}
		log.Info("Stopping server gracefully")
		s.Stop()
	}()
	s.Start()
}

// Wait blocks until server is shutted down.
func (s *Server) Wait() {
	<-s.stopChan
}

// Stop stops the server
func (s *Server) Stop() {
	defer log.Info("Server stopped")
	var wg sync.WaitGroup
	for sepn, sep := range s.serverEntryPoints {
		wg.Add(1)
		go func(serverEntryPointName string, serverEntryPoint *serverEntryPoint) {
			defer wg.Done()
			graceTimeOut := time.Duration(s.globalConfiguration.LifeCycle.GraceTimeOut)
			ctx, cancel := context.WithTimeout(context.Background(), graceTimeOut)
			log.Debugf("Waiting %s seconds before killing connections on entrypoint %s...", graceTimeOut, serverEntryPointName)
			serverEntryPoint.Shutdown(ctx)
			cancel()
			log.Debugf("Entrypoint %s closed", serverEntryPointName)
		}(sepn, sep)
	}
	wg.Wait()
	s.stopChan <- true
}

// Close destroys the server
func (s *Server) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	go func(ctx context.Context) {
		<-ctx.Done()
		if ctx.Err() == context.Canceled {
			return
		} else if ctx.Err() == context.DeadlineExceeded {
			panic("Timeout while stopping traefik, killing instance ✝")
		}
	}(ctx)
	stopMetricsClients()
	s.stopLeadership()
	s.routinesPool.Cleanup()
	close(s.configurationChan)
	close(s.configurationValidatedChan)
	signal.Stop(s.signals)
	close(s.signals)
	close(s.stopChan)
	if s.accessLoggerMiddleware != nil {
		if err := s.accessLoggerMiddleware.Close(); err != nil {
			log.Errorf("Error closing access log file: %s", err)
		}
	}
	cancel()
}

func (s *Server) startLeadership() {
	if s.leadership != nil {
		s.leadership.Participate(s.routinesPool)
	}
}

func (s *Server) stopLeadership() {
	if s.leadership != nil {
		s.leadership.Stop()
	}
}

func (s *Server) startHTTPServers() {
	s.serverEntryPoints = s.buildServerEntryPoints()

	for newServerEntryPointName, newServerEntryPoint := range s.serverEntryPoints {
		serverEntryPoint := s.setupServerEntryPoint(newServerEntryPointName, newServerEntryPoint)
		go s.startServer(serverEntryPoint)
	}
}

func (s *Server) listenProviders(stop chan bool) {
	for {
		select {
		case <-stop:
			return
		case configMsg, ok := <-s.configurationChan:
			if !ok || configMsg.Configuration == nil {
				return
			}
			s.preLoadConfiguration(configMsg)
		}
	}
}

// AddListener adds a new listener function used when new configuration is provided
func (s *Server) AddListener(listener func(types.Configuration)) {
	if s.configurationListeners == nil {
		s.configurationListeners = make([]func(types.Configuration), 0)
	}
	s.configurationListeners = append(s.configurationListeners, listener)
}

// getCertificate allows to customize tlsConfig.GetCertificate behavior to get the certificates inserted dynamically
func (s *serverEntryPoint) getCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	domainToCheck := types.CanonicalDomain(clientHello.ServerName)

	if s.tlsALPNGetter != nil {
		cert, err := s.tlsALPNGetter(domainToCheck)
		if err != nil {
			return nil, err
		}

		if cert != nil {
			return cert, nil
		}
	}

	bestCertificate := s.certs.GetBestCertificate(clientHello)
	if bestCertificate != nil {
		return bestCertificate, nil
	}

	if s.onDemandListener != nil && len(domainToCheck) > 0 {
		// Only check for an onDemandCert if there is a domain name
		return s.onDemandListener(domainToCheck)
	}

	if s.certs.SniStrict {
		return nil, fmt.Errorf("strict SNI enabled - No certificate found for domain: %q, closing connection", domainToCheck)
	}

	log.Debugf("Serving default cert for request: %q", domainToCheck)
	return s.certs.DefaultCertificate, nil
}

func (s *Server) startProvider() {
	// start providers
	jsonConf, err := json.Marshal(s.provider)
	if err != nil {
		log.Debugf("Unable to marshal provider conf %T with error: %v", s.provider, err)
	}
	log.Infof("Starting provider %T %s", s.provider, jsonConf)
	currentProvider := s.provider
	safe.Go(func() {
		err := currentProvider.Provide(s.configurationChan, s.routinesPool)
		if err != nil {
			log.Errorf("Error starting provider %T: %s", s.provider, err)
		}
	})
}

// creates a TLS config that allows terminating HTTPS for multiple domains using SNI
func (s *Server) createTLSConfig(entryPointName string, tlsOption *traefiktls.TLS, router *middlewares.HandlerSwitcher) (*tls.Config, error) {
	if tlsOption == nil {
		return nil, nil
	}

	config, err := tlsOption.Certificates.CreateTLSConfig(entryPointName)
	if err != nil {
		return nil, err
	}

	s.serverEntryPoints[entryPointName].certs.DynamicCerts.Set(make(map[string]*tls.Certificate))

	// ensure http2 enabled
	config.NextProtos = []string{"h2", "http/1.1", acme.ACMETLS1Protocol}

	if len(tlsOption.ClientCA.Files) > 0 {
		pool := x509.NewCertPool()
		for _, caFile := range tlsOption.ClientCA.Files {
			data, err := ioutil.ReadFile(caFile)
			if err != nil {
				return nil, err
			}
			ok := pool.AppendCertsFromPEM(data)
			if !ok {
				return nil, fmt.Errorf("invalid certificate(s) in %s", caFile)
			}
		}
		config.ClientCAs = pool
		if tlsOption.ClientCA.Optional {
			config.ClientAuth = tls.VerifyClientCertIfGiven
		} else {
			config.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}

	if s.globalConfiguration.ACME != nil {
		if entryPointName == s.globalConfiguration.ACME.EntryPoint {
			checkOnDemandDomain := func(domain string) bool {
				routeMatch := &mux.RouteMatch{}
				match := router.GetHandler().Match(&http.Request{URL: &url.URL{}, Host: domain}, routeMatch)
				if match && routeMatch.Route != nil {
					return true
				}
				return false
			}

			err := s.globalConfiguration.ACME.CreateClusterConfig(s.leadership, config, s.serverEntryPoints[entryPointName].certs.DynamicCerts, checkOnDemandDomain)
			if err != nil {
				return nil, err
			}
		}
	} else {
		config.GetCertificate = s.serverEntryPoints[entryPointName].getCertificate
	}

	if len(config.Certificates) != 0 {
		certMap := s.buildNameOrIPToCertificate(config.Certificates)

		if s.entryPoints[entryPointName].CertificateStore != nil {
			s.entryPoints[entryPointName].CertificateStore.StaticCerts.Set(certMap)
		}
	}

	// Remove certs from the TLS config object
	config.Certificates = []tls.Certificate{}

	// Set the minimum TLS version if set in the config TOML
	if minConst, exists := traefiktls.MinVersion[s.entryPoints[entryPointName].Configuration.TLS.MinVersion]; exists {
		config.PreferServerCipherSuites = true
		config.MinVersion = minConst
	}

	// Set the list of CipherSuites if set in the config TOML
	if s.entryPoints[entryPointName].Configuration.TLS.CipherSuites != nil {
		// if our list of CipherSuites is defined in the entrypoint config, we can re-initilize the suites list as empty
		config.CipherSuites = make([]uint16, 0)
		for _, cipher := range s.entryPoints[entryPointName].Configuration.TLS.CipherSuites {
			if cipherConst, exists := traefiktls.CipherSuites[cipher]; exists {
				config.CipherSuites = append(config.CipherSuites, cipherConst)
			} else {
				// CipherSuite listed in the toml does not exist in our listed
				return nil, fmt.Errorf("invalid CipherSuite: %s", cipher)
			}
		}
	}

	return config, nil
}

func (s *Server) startServer(serverEntryPoint *serverEntryPoint) {
	log.Infof("Starting server on %s", serverEntryPoint.httpServer.Addr)

	var err error
	if serverEntryPoint.httpServer.TLSConfig != nil {
		err = serverEntryPoint.httpServer.ServeTLS(serverEntryPoint.listener, "", "")
	} else {
		err = serverEntryPoint.httpServer.Serve(serverEntryPoint.listener)
	}

	if err != http.ErrServerClosed {
		log.Error("Error creating server: ", err)
	}
}

func (s *Server) setupServerEntryPoint(newServerEntryPointName string, newServerEntryPoint *serverEntryPoint) *serverEntryPoint {
	serverMiddlewares, err := s.buildServerEntryPointMiddlewares(newServerEntryPointName)
	if err != nil {
		log.Fatal("Error preparing server: ", err)
	}

	newSrv, listener, err := s.prepareServer(newServerEntryPointName, s.entryPoints[newServerEntryPointName].Configuration, newServerEntryPoint.httpRouter, serverMiddlewares)
	if err != nil {
		log.Fatal("Error preparing server: ", err)
	}

	serverEntryPoint := s.serverEntryPoints[newServerEntryPointName]
	serverEntryPoint.httpServer = newSrv
	serverEntryPoint.listener = listener

	serverEntryPoint.hijackConnectionTracker = newHijackConnectionTracker()
	serverEntryPoint.httpServer.ConnState = func(conn net.Conn, state http.ConnState) {
		switch state {
		case http.StateHijacked:
			serverEntryPoint.hijackConnectionTracker.AddHijackedConnection(conn)
		case http.StateClosed:
			serverEntryPoint.hijackConnectionTracker.RemoveHijackedConnection(conn)
		}
	}

	return serverEntryPoint
}

func (s *Server) prepareServer(entryPointName string, entryPoint *configuration.EntryPoint, router *middlewares.HandlerSwitcher, middlewares []negroni.Handler) (*h2c.Server, net.Listener, error) {
	readTimeout, writeTimeout, idleTimeout := buildServerTimeouts(s.globalConfiguration)
	log.Infof("Preparing server %s %+v with readTimeout=%s writeTimeout=%s idleTimeout=%s", entryPointName, entryPoint, readTimeout, writeTimeout, idleTimeout)

	// middlewares
	n := negroni.New()
	for _, middleware := range middlewares {
		n.Use(middleware)
	}
	n.UseHandler(router)

	internalMuxRouter := s.buildInternalRouter(entryPointName)
	internalMuxRouter.NotFoundHandler = n

	tlsConfig, err := s.createTLSConfig(entryPointName, entryPoint.TLS, router)
	if err != nil {
		return nil, nil, fmt.Errorf("error creating TLS config: %v", err)
	}

	listener, err := net.Listen("tcp", entryPoint.Address)
	if err != nil {
		return nil, nil, fmt.Errorf("error opening listener: %v", err)
	}

	if entryPoint.ProxyProtocol != nil {
		listener, err = buildProxyProtocolListener(entryPoint, listener)
		if err != nil {
			return nil, nil, err
		}
	}

	return &h2c.Server{
			Server: &http.Server{
				Addr:         entryPoint.Address,
				Handler:      internalMuxRouter,
				TLSConfig:    tlsConfig,
				ReadTimeout:  readTimeout,
				WriteTimeout: writeTimeout,
				IdleTimeout:  idleTimeout,
				ErrorLog:     httpServerLogger,
			},
		},
		listener,
		nil
}

func buildProxyProtocolListener(entryPoint *configuration.EntryPoint, listener net.Listener) (net.Listener, error) {
	IPs, err := whitelist.NewIP(entryPoint.ProxyProtocol.TrustedIPs, entryPoint.ProxyProtocol.Insecure, false)
	if err != nil {
		return nil, fmt.Errorf("error creating whitelist: %s", err)
	}

	log.Infof("Enabling ProxyProtocol for trusted IPs %v", entryPoint.ProxyProtocol.TrustedIPs)

	return &proxyproto.Listener{
		Listener: listener,
		SourceCheck: func(addr net.Addr) (bool, error) {
			ip, ok := addr.(*net.TCPAddr)
			if !ok {
				return false, fmt.Errorf("type error %v", addr)
			}

			return IPs.ContainsIP(ip.IP), nil
		},
	}, nil
}

func (s *Server) buildInternalRouter(entryPointName string) *mux.Router {
	internalMuxRouter := mux.NewRouter()
	internalMuxRouter.StrictSlash(true)
	internalMuxRouter.SkipClean(true)

	if entryPoint, ok := s.entryPoints[entryPointName]; ok && entryPoint.InternalRouter != nil {
		entryPoint.InternalRouter.AddRoutes(internalMuxRouter)

		if s.globalConfiguration.API != nil && s.globalConfiguration.API.EntryPoint == entryPointName && s.leadership != nil {
			s.leadership.AddRoutes(internalMuxRouter)

		}
	}

	return internalMuxRouter
}

func buildServerTimeouts(globalConfig configuration.GlobalConfiguration) (readTimeout, writeTimeout, idleTimeout time.Duration) {
	readTimeout = time.Duration(0)
	writeTimeout = time.Duration(0)
	if globalConfig.RespondingTimeouts != nil {
		readTimeout = time.Duration(globalConfig.RespondingTimeouts.ReadTimeout)
		writeTimeout = time.Duration(globalConfig.RespondingTimeouts.WriteTimeout)
	}

	if globalConfig.RespondingTimeouts != nil {
		idleTimeout = time.Duration(globalConfig.RespondingTimeouts.IdleTimeout)
	} else {
		idleTimeout = configuration.DefaultIdleTimeout
	}

	return readTimeout, writeTimeout, idleTimeout
}

func (s *Server) buildEntryPoints(globalConfiguration configuration.GlobalConfiguration) map[string]*serverEntryPoint {
	serverEntryPoints := make(map[string]*serverEntryPoint)
	for entryPointName := range globalConfiguration.EntryPoints {
		router := s.buildDefaultHTTPRouter()
		serverEntryPoints[entryPointName] = &serverEntryPoint{
			httpRouter: middlewares.NewHandlerSwitcher(router),
		}
	}
	return serverEntryPoints
}

// getRoundTripper will either use server.defaultForwardingRoundTripper or create a new one
// given a custom TLS configuration is passed and the passTLSCert option is set to true.
func (s *Server) getRoundTripper(entryPointName string, globalConfiguration configuration.GlobalConfiguration, passTLSCert bool, tls *traefiktls.TLS) (http.RoundTripper, error) {
	if passTLSCert {
		tlsConfig, err := createClientTLSConfig(entryPointName, tls)
		if err != nil {
			log.Errorf("Failed to create TLSClientConfig: %s", err)
			return nil, err
		}

		transport := createHTTPTransport(globalConfiguration)
		transport.TLSClientConfig = tlsConfig
		return transport, nil
	}

	return s.defaultForwardingRoundTripper, nil
}

// loadConfig returns a new gorilla.mux Route from the specified global configuration and the dynamic
// provider configurations.
func (s *Server) loadConfig(configurations types.Configurations, globalConfiguration configuration.GlobalConfiguration) (map[string]*serverEntryPoint, error) {
	serverEntryPoints := s.buildEntryPoints(globalConfiguration)
	redirectHandlers := make(map[string]negroni.Handler)
	backends := map[string]http.Handler{}
	backendsHealthCheck := map[string]*healthcheck.BackendHealthCheck{}
	var errorPageHandlers []*errorpages.Handler

	errorHandler := NewRecordingErrorHandler(middlewares.DefaultNetErrorRecorder{})

	for providerName, config := range configurations {
		frontendNames := sortedFrontendNamesForConfig(config)
	frontend:
		for _, frontendName := range frontendNames {
			frontend := config.Frontends[frontendName]

			log.Debugf("Creating frontend %s", frontendName)

			var frontendEntryPoints []string
			for _, entryPointName := range frontend.EntryPoints {
				if _, ok := serverEntryPoints[entryPointName]; !ok {
					log.Errorf("Undefined entrypoint '%s' for frontend %s", entryPointName, frontendName)
				} else {
					frontendEntryPoints = append(frontendEntryPoints, entryPointName)
				}
			}
			frontend.EntryPoints = frontendEntryPoints

			if len(frontend.EntryPoints) == 0 {
				log.Errorf("No entrypoint defined for frontend %s", frontendName)
				log.Errorf("Skipping frontend %s...", frontendName)
				continue frontend
			}
			for _, entryPointName := range frontend.EntryPoints {
				log.Debugf("Wiring frontend %s to entryPoint %s", frontendName, entryPointName)

				newServerRoute := &types.ServerRoute{Route: serverEntryPoints[entryPointName].httpRouter.GetHandler().NewRoute().Name(frontendName)}
				for routeName, route := range frontend.Routes {
					err := getRoute(newServerRoute, &route)
					if err != nil {
						log.Errorf("Error creating route for frontend %s: %v", frontendName, err)
						log.Errorf("Skipping frontend %s...", frontendName)
						continue frontend
					}
					log.Debugf("Creating route %s %s", routeName, route.Rule)
				}

				entryPoint := globalConfiguration.EntryPoints[entryPointName]
				n := negroni.New()
				if entryPoint.Redirect != nil && entryPointName != entryPoint.Redirect.EntryPoint {
					if redirectHandlers[entryPointName] != nil {
						n.Use(redirectHandlers[entryPointName])
					} else if handler, err := s.buildRedirectHandler(entryPointName, entryPoint.Redirect); err != nil {
						log.Errorf("Error loading entrypoint configuration for frontend %s: %v", frontendName, err)
						log.Errorf("Skipping frontend %s...", frontendName)
						continue frontend
					} else {
						handlerToUse := s.wrapNegroniHandlerWithAccessLog(handler, fmt.Sprintf("entrypoint redirect for %s", frontendName))
						n.Use(handlerToUse)
						redirectHandlers[entryPointName] = handlerToUse
					}
				}
				if backends[entryPointName+providerName+frontend.Backend] == nil {
					log.Debugf("Creating backend %s", frontend.Backend)

					roundTripper, err := s.getRoundTripper(entryPointName, globalConfiguration, frontend.PassTLSCert, entryPoint.TLS)
					if err != nil {
						log.Errorf("Failed to create RoundTripper for frontend %s: %v", frontendName, err)
						log.Errorf("Skipping frontend %s...", frontendName)
						continue frontend
					}

					rewriter, err := NewHeaderRewriter(entryPoint.ForwardedHeaders.TrustedIPs, entryPoint.ForwardedHeaders.Insecure)
					if err != nil {
						log.Errorf("Error creating rewriter for frontend %s: %v", frontendName, err)
						log.Errorf("Skipping frontend %s...", frontendName)
						continue frontend
					}

					headerMiddleware := middlewares.NewHeaderFromStruct(frontend.Headers)
					secureMiddleware := middlewares.NewSecure(frontend.Headers)

					var responseModifier = buildModifyResponse(secureMiddleware, headerMiddleware)
					var fwd http.Handler

					fwd, err = forward.New(
						forward.Stream(true),
						forward.PassHostHeader(frontend.PassHostHeader),
						forward.RoundTripper(roundTripper),
						forward.ErrorHandler(errorHandler),
						forward.Rewriter(rewriter),
						forward.ResponseModifier(responseModifier),
					)

					if err != nil {
						log.Errorf("Error creating forwarder for frontend %s: %v", frontendName, err)
						log.Errorf("Skipping frontend %s...", frontendName)
						continue frontend
					}

					if s.tracingMiddleware.IsEnabled() {
						tm := s.tracingMiddleware.NewForwarderMiddleware(frontendName, frontend.Backend)

						next := fwd
						fwd = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							tm.ServeHTTP(w, r, next.ServeHTTP)
						})
					}

					var rr *roundrobin.RoundRobin
					var saveFrontend http.Handler
					if s.accessLoggerMiddleware != nil {
						saveBackend := accesslog.NewSaveBackend(fwd, frontend.Backend)
						saveFrontend = accesslog.NewSaveFrontend(saveBackend, frontendName)
						rr, _ = roundrobin.New(saveFrontend)
					} else {
						rr, _ = roundrobin.New(fwd)
					}

					if config.Backends[frontend.Backend] == nil {
						log.Errorf("Undefined backend '%s' for frontend %s", frontend.Backend, frontendName)
						log.Errorf("Skipping frontend %s...", frontendName)
						continue frontend
					}

					lbMethod, err := types.NewLoadBalancerMethod(config.Backends[frontend.Backend].LoadBalancer)
					if err != nil {
						log.Errorf("Error loading load balancer method '%+v' for frontend %s: %v", config.Backends[frontend.Backend].LoadBalancer, frontendName, err)
						log.Errorf("Skipping frontend %s...", frontendName)
						continue frontend
					}

					var sticky *roundrobin.StickySession
					var cookieName string
					if stickiness := config.Backends[frontend.Backend].LoadBalancer.Stickiness; stickiness != nil {
						cookieName = cookie.GetName(stickiness.CookieName, frontend.Backend)
						sticky = roundrobin.NewStickySession(cookieName)
					}

					var lb http.Handler
					switch lbMethod {
					case types.Drr:
						log.Debugf("Creating load-balancer drr")
						rebalancer, _ := roundrobin.NewRebalancer(rr)
						if sticky != nil {
							log.Debugf("Sticky session with cookie %v", cookieName)
							rebalancer, _ = roundrobin.NewRebalancer(rr, roundrobin.RebalancerStickySession(sticky))
						}
						lb = rebalancer
						if err := s.configureLBServers(rebalancer, config, frontend); err != nil {
							log.Errorf("Skipping frontend %s...", frontendName)
							continue frontend
						}
						hcOpts := parseHealthCheckOptions(rebalancer, frontend.Backend, config.Backends[frontend.Backend].HealthCheck, globalConfiguration.HealthCheck)
						if hcOpts != nil {
							log.Debugf("Setting up backend health check %s", *hcOpts)
							hcOpts.Transport = s.defaultForwardingRoundTripper
							backendsHealthCheck[entryPointName+frontend.Backend] = healthcheck.NewBackendHealthCheck(*hcOpts, frontend.Backend)
						}
						lb = middlewares.NewEmptyBackendHandler(rebalancer, lb)
					case types.Wrr:
						log.Debugf("Creating load-balancer wrr")
						if sticky != nil {
							log.Debugf("Sticky session with cookie %v", cookieName)
							if s.accessLoggerMiddleware != nil {
								rr, _ = roundrobin.New(saveFrontend, roundrobin.EnableStickySession(sticky))
							} else {
								rr, _ = roundrobin.New(fwd, roundrobin.EnableStickySession(sticky))
							}
						}
						lb = rr
						if err := s.configureLBServers(rr, config, frontend); err != nil {
							log.Errorf("Skipping frontend %s...", frontendName)
							continue frontend
						}
						hcOpts := parseHealthCheckOptions(rr, frontend.Backend, config.Backends[frontend.Backend].HealthCheck, globalConfiguration.HealthCheck)
						if hcOpts != nil {
							log.Debugf("Setting up backend health check %s", *hcOpts)
							hcOpts.Transport = s.defaultForwardingRoundTripper
							backendsHealthCheck[entryPointName+frontend.Backend] = healthcheck.NewBackendHealthCheck(*hcOpts, frontend.Backend)
						}
						lb = middlewares.NewEmptyBackendHandler(rr, lb)
					}

					if len(frontend.Errors) > 0 {
						for errorPageName, errorPage := range frontend.Errors {
							if frontend.Backend == errorPage.Backend {
								log.Errorf("Error when creating error page %q for frontend %q: error pages backend %q is the same as backend for the frontend (infinite call risk).",
									errorPageName, frontendName, errorPage.Backend)
							} else if config.Backends[errorPage.Backend] == nil {
								log.Errorf("Error when creating error page %q for frontend %q: the backend %q doesn't exist.",
									errorPageName, errorPage.Backend)
							} else {
								errorPagesHandler, err := errorpages.NewHandler(errorPage, entryPointName+providerName+errorPage.Backend)
								if err != nil {
									log.Errorf("Error creating error pages: %v", err)
								} else {
									if errorPageServer, ok := config.Backends[errorPage.Backend].Servers["error"]; ok {
										errorPagesHandler.FallbackURL = errorPageServer.URL
									}

									errorPageHandlers = append(errorPageHandlers, errorPagesHandler)
									n.Use(errorPagesHandler)
								}
							}
						}
					}

					if frontend.RateLimit != nil && len(frontend.RateLimit.RateSet) > 0 {
						lb, err = s.buildRateLimiter(lb, frontend.RateLimit)
						if err != nil {
							log.Errorf("Error creating rate limiter: %v", err)
							log.Errorf("Skipping frontend %s...", frontendName)
							continue frontend
						}
						lb = s.wrapHTTPHandlerWithAccessLog(lb, fmt.Sprintf("rate limit for %s", frontendName))
					}

					maxConns := config.Backends[frontend.Backend].MaxConn
					if maxConns != nil && maxConns.Amount != 0 {
						extractFunc, err := utils.NewExtractor(maxConns.ExtractorFunc)
						if err != nil {
							log.Errorf("Error creating connection limit: %v", err)
							log.Errorf("Skipping frontend %s...", frontendName)
							continue frontend
						}

						log.Debugf("Creating load-balancer connection limit")

						lb, err = connlimit.New(lb, extractFunc, maxConns.Amount)
						if err != nil {
							log.Errorf("Error creating connection limit: %v", err)
							log.Errorf("Skipping frontend %s...", frontendName)
							continue frontend
						}
						lb = s.wrapHTTPHandlerWithAccessLog(lb, fmt.Sprintf("connection limit for %s", frontendName))
					}

					if globalConfiguration.Retry != nil {
						countServers := len(config.Backends[frontend.Backend].Servers)
						lb = s.buildRetryMiddleware(lb, globalConfiguration, countServers, frontend.Backend)
					}

					if s.metricsRegistry.IsEnabled() {
						n.Use(middlewares.NewBackendMetricsMiddleware(s.metricsRegistry, frontend.Backend))
					}

					ipWhitelistMiddleware, err := buildIPWhiteLister(frontend.WhiteList, frontend.WhitelistSourceRange)
					if err != nil {
						log.Errorf("Error creating IP Whitelister: %s", err)
					} else if ipWhitelistMiddleware != nil {
						n.Use(
							s.tracingMiddleware.NewNegroniHandlerWrapper(
								"IP whitelist",
								s.wrapNegroniHandlerWithAccessLog(ipWhitelistMiddleware, fmt.Sprintf("ipwhitelister for %s", frontendName)),
								false))
						log.Debugf("Configured IP Whitelists: %s", frontend.WhitelistSourceRange)
					}

					if frontend.Redirect != nil && entryPointName != frontend.Redirect.EntryPoint {
						rewrite, err := s.buildRedirectHandler(entryPointName, frontend.Redirect)
						if err != nil {
							log.Errorf("Error creating Frontend Redirect: %v", err)
						} else {
							n.Use(s.wrapNegroniHandlerWithAccessLog(rewrite, fmt.Sprintf("frontend redirect for %s", frontendName)))
							log.Debugf("Frontend %s redirect created", frontendName)
						}
					}

					if len(frontend.BasicAuth) > 0 {
						users := types.Users{}
						for _, user := range frontend.BasicAuth {
							users = append(users, user)
						}

						auth := &types.Auth{}
						auth.Basic = &types.Basic{
							Users: users,
						}
						authMiddleware, err := mauth.NewAuthenticator(auth, s.tracingMiddleware)
						if err != nil {
							log.Errorf("Error creating Auth: %s", err)
						} else {
							n.Use(s.wrapNegroniHandlerWithAccessLog(authMiddleware, fmt.Sprintf("Auth for %s", frontendName)))
						}
					}

					if frontend.Jwt != nil && (frontend.Jwt.Issuer != "" || frontend.Jwt.Audience != "" || frontend.Jwt.JwksAddress != "" || frontend.Jwt.OidcDiscoveryAddress != "" || frontend.Jwt.ClientSecret != "") {
						jwtValidatorMiddleware, err := mjwt.NewJwtValidator(frontend.Jwt, s.tracingMiddleware)

						if err != nil {
							log.Errorf("Error creating Jwt Validator: %s", err)
						} else {
							log.Info(" Adding jwt middleware for: %s \n  Issuer: %s\n  Audience: %s\n  Issuer: %s\n  ClientSecret: %t\n  PublicKey: %t\n  OidcDiscoveryAddress: %s\n  JwksAddress: %s\n  SsoAddressTemplate: %s", frontendName, frontend.Jwt.Issuer, frontend.Jwt.Audience, frontend.Jwt.ClientSecret != "", frontend.Jwt.PublicKey != "", frontend.Jwt.OidcDiscoveryAddress, frontend.Jwt.JwksAddress, frontend.Jwt.SsoAddressTemplate)
							n.Use(s.wrapNegroniHandlerWithAccessLog(jwtValidatorMiddleware.Handler, fmt.Sprintf("Jwt Validator for %s", frontendName)))
						}
					}

					if headerMiddleware != nil {
						log.Debugf("Adding header middleware for frontend %s", frontendName)
						n.Use(s.tracingMiddleware.NewNegroniHandlerWrapper("Header", headerMiddleware, false))
					}

					if secureMiddleware != nil {
						log.Debugf("Adding secure middleware for frontend %s", frontendName)
						n.UseFunc(secureMiddleware.HandlerFuncWithNextForRequestOnly)
					}

					if config.Backends[frontend.Backend].Buffering != nil {
						bufferedLb, err := s.buildBufferingMiddleware(lb, config.Backends[frontend.Backend].Buffering)

						if err != nil {
							log.Errorf("Error setting up buffering middleware: %s", err)
						} else {
							lb = bufferedLb
						}
					}

					if config.Backends[frontend.Backend].CircuitBreaker != nil {
						log.Debugf("Creating circuit breaker %s", config.Backends[frontend.Backend].CircuitBreaker.Expression)
						expression := config.Backends[frontend.Backend].CircuitBreaker.Expression
						circuitBreaker, err := middlewares.NewCircuitBreaker(lb, expression, middlewares.NewCircuitBreakerOptions(expression))
						if err != nil {
							log.Errorf("Error creating circuit breaker: %v", err)
							log.Errorf("Skipping frontend %s...", frontendName)
							continue frontend
						}
						n.Use(s.tracingMiddleware.NewNegroniHandlerWrapper("Circuit breaker", circuitBreaker, false))
					} else {
						n.UseHandler(lb)
					}
					backends[entryPointName+providerName+frontend.Backend] = n
				} else {
					log.Debugf("Reusing backend %s", frontend.Backend)
				}
				if frontend.Priority > 0 {
					newServerRoute.Route.Priority(frontend.Priority)
				}
				s.wireFrontendBackend(newServerRoute, backends[entryPointName+providerName+frontend.Backend])

				err := newServerRoute.Route.GetError()
				if err != nil {
					log.Errorf("Error building route: %s", err)
				}
			}
		}
	}

	for _, errorPageHandler := range errorPageHandlers {
		if handler, ok := backends[errorPageHandler.BackendName]; ok {
			errorPageHandler.PostLoad(handler)
		} else {
			errorPageHandler.PostLoad(nil)
		}
	}

	healthcheck.GetHealthCheck(s.metricsRegistry).SetBackendsConfiguration(s.routinesPool.Ctx(), backendsHealthCheck)

	// Get new certificates list sorted per entrypoints
	// Update certificates
	entryPointsCertificates, err := s.loadHTTPSConfiguration(configurations, globalConfiguration.DefaultEntryPoints)

	// Sort routes and update certificates
	for serverEntryPointName, serverEntryPoint := range serverEntryPoints {
		serverEntryPoint.httpRouter.GetHandler().SortRoutes()
		if _, exists := entryPointsCertificates[serverEntryPointName]; exists {
			serverEntryPoint.certs.Set(entryPointsCertificates[serverEntryPointName])
		}
	}

	return serverEntryPoints, err
}

func (s *Server) configureLBServers(lb healthcheck.LoadBalancer, config *types.Configuration, frontend *types.Frontend) error {
	for name, srv := range config.Backends[frontend.Backend].Servers {
		u, err := url.Parse(srv.URL)
		if err != nil {
			log.Errorf("Error parsing server URL %s: %v", srv.URL, err)
			return err
		}
		log.Debugf("Creating server %s at %s with weight %d", name, u, srv.Weight)
		if err := lb.UpsertServer(u, roundrobin.Weight(srv.Weight)); err != nil {
			log.Errorf("Error adding server %s to load balancer: %v", srv.URL, err)
			return err
		}
		s.metricsRegistry.BackendServerUpGauge().With("backend", frontend.Backend, "url", srv.URL).Set(1)
	}
	return nil
}

func buildIPWhiteLister(whiteList *types.WhiteList, wlRange []string) (*middlewares.IPWhiteLister, error) {
	if whiteList != nil &&
		len(whiteList.SourceRange) > 0 {
		return middlewares.NewIPWhiteLister(whiteList.SourceRange, whiteList.UseXForwardedFor)
	} else if len(wlRange) > 0 {
		return middlewares.NewIPWhiteLister(wlRange, false)
	}
	return nil, nil
}

func (s *Server) wireFrontendBackend(serverRoute *types.ServerRoute, handler http.Handler) {
	// path replace - This needs to always be the very last on the handler chain (first in the order in this function)
	// -- Replacing Path should happen at the very end of the Modifier chain, after all the Matcher+Modifiers ran
	if len(serverRoute.ReplacePath) > 0 {
		handler = &middlewares.ReplacePath{
			Path:    serverRoute.ReplacePath,
			Handler: handler,
		}
	}

	if len(serverRoute.ReplacePathRegex) > 0 {
		sp := strings.Split(serverRoute.ReplacePathRegex, " ")
		if len(sp) == 2 {
			handler = middlewares.NewReplacePathRegexHandler(sp[0], sp[1], handler)
		} else {
			log.Warnf("Invalid syntax for ReplacePathRegex: %s. Separate the regular expression and the replacement by a space.", serverRoute.ReplacePathRegex)
		}
	}

	// add prefix - This needs to always be right before ReplacePath on the chain (second in order in this function)
	// -- Adding Path Prefix should happen after all *Strip Matcher+Modifiers ran, but before Replace (in case it's configured)
	if len(serverRoute.AddPrefix) > 0 {
		handler = &middlewares.AddPrefix{
			Prefix:  serverRoute.AddPrefix,
			Handler: handler,
		}
	}

	// strip prefix
	if len(serverRoute.StripPrefixes) > 0 {
		handler = &middlewares.StripPrefix{
			Prefixes: serverRoute.StripPrefixes,
			Handler:  handler,
		}
	}

	// strip prefix with regex
	if len(serverRoute.StripPrefixesRegex) > 0 {
		handler = middlewares.NewStripPrefixRegex(handler, serverRoute.StripPrefixesRegex)
	}

	serverRoute.Route.Handler(handler)
}

func (s *Server) buildRedirectHandler(srcEntryPointName string, opt *types.Redirect) (negroni.Handler, error) {
	// entry point redirect
	if len(opt.EntryPoint) > 0 {
		entryPoint := s.globalConfiguration.EntryPoints[opt.EntryPoint]
		if entryPoint == nil {
			return nil, fmt.Errorf("unknown target entrypoint %q", srcEntryPointName)
		}
		log.Debugf("Creating entry point redirect %s -> %s", srcEntryPointName, opt.EntryPoint)
		return redirect.NewEntryPointHandler(entryPoint, opt.Permanent)
	}

	// regex redirect
	redirection, err := redirect.NewRegexHandler(opt.Regex, opt.Replacement, opt.Permanent)
	if err != nil {
		return nil, err
	}
	log.Debugf("Creating regex redirect %s -> %s -> %s", srcEntryPointName, opt.Regex, opt.Replacement)

	return redirection, nil
}

func (s *Server) buildDefaultHTTPRouter() *mux.Router {
	router := mux.NewRouter()
	router.NotFoundHandler = s.wrapHTTPHandlerWithAccessLog(http.HandlerFunc(notFoundHandler), "backend not found")
	router.StrictSlash(true)
	router.SkipClean(true)
	return router
}

func parseHealthCheckOptions(lb healthcheck.LoadBalancer, backend string, hc *types.HealthCheck, hcConfig *configuration.HealthCheckConfig) *healthcheck.Options {
	if hc == nil || hc.Path == "" || hcConfig == nil {
		return nil
	}

	interval := time.Duration(hcConfig.Interval)
	if hc.Interval != "" {
		intervalOverride, err := time.ParseDuration(hc.Interval)
		switch {
		case err != nil:
			log.Errorf("Illegal healthcheck interval for backend '%s': %s", backend, err)
		case intervalOverride <= 0:
			log.Errorf("Healthcheck interval smaller than zero for backend '%s', backend", backend)
		default:
			interval = intervalOverride
		}
	}

	return &healthcheck.Options{
		Hostname: hc.Hostname,
		Headers:  hc.Headers,
		Path:     hc.Path,
		Port:     hc.Port,
		Interval: interval,
		LB:       lb,
	}
}

func getRoute(serverRoute *types.ServerRoute, route *types.Route) error {
	rules := rules.Rules{Route: serverRoute}
	newRoute, err := rules.Parse(route.Rule)
	if err != nil {
		return err
	}
	newRoute.Priority(serverRoute.Route.GetPriority() + len(route.Rule))
	serverRoute.Route = newRoute
	return nil
}

func sortedFrontendNamesForConfig(configuration *types.Configuration) []string {
	var keys []string
	for key := range configuration.Frontends {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func configureFrontends(frontends map[string]*types.Frontend, defaultEntrypoints []string) {
	for _, frontend := range frontends {
		// default endpoints if not defined in frontends
		if len(frontend.EntryPoints) == 0 {
			frontend.EntryPoints = defaultEntrypoints
		}
	}
}

func configureBackends(backends map[string]*types.Backend) {
	for backendName := range backends {
		backend := backends[backendName]
		if backend.LoadBalancer != nil && backend.LoadBalancer.Sticky {
			log.Warnf("Deprecated configuration found: %s. Please use %s.", "backend.LoadBalancer.Sticky", "backend.LoadBalancer.Stickiness")
		}

		_, err := types.NewLoadBalancerMethod(backend.LoadBalancer)
		if err == nil {
			if backend.LoadBalancer != nil && backend.LoadBalancer.Stickiness == nil && backend.LoadBalancer.Sticky {
				backend.LoadBalancer.Stickiness = &types.Stickiness{
					CookieName: "_TRAEFIK_BACKEND",
				}
			}
		} else {
			log.Debugf("Validation of load balancer method for backend %s failed: %s. Using default method wrr.", backendName, err)

			var stickiness *types.Stickiness
			if backend.LoadBalancer != nil {
				if backend.LoadBalancer.Stickiness == nil {
					if backend.LoadBalancer.Sticky {
						stickiness = &types.Stickiness{
							CookieName: "_TRAEFIK_BACKEND",
						}
					}
				} else {
					stickiness = backend.LoadBalancer.Stickiness
				}
			}
			backend.LoadBalancer = &types.LoadBalancer{
				Method:     "wrr",
				Stickiness: stickiness,
			}
		}
	}
}

func registerMetricClients(metricsConfig *types.Metrics) metrics.Registry {
	if metricsConfig == nil {
		return metrics.NewVoidRegistry()
	}

	var registries []metrics.Registry
	if metricsConfig.Prometheus != nil {
		prometheusRegister := metrics.RegisterPrometheus(metricsConfig.Prometheus)
		if prometheusRegister != nil {
			registries = append(registries, prometheusRegister)
			log.Debug("Configured Prometheus metrics")
		}
	}
	if metricsConfig.Datadog != nil {
		registries = append(registries, metrics.RegisterDatadog(metricsConfig.Datadog))
		log.Debugf("Configured DataDog metrics pushing to %s once every %s", metricsConfig.Datadog.Address, metricsConfig.Datadog.PushInterval)
	}
	if metricsConfig.StatsD != nil {
		registries = append(registries, metrics.RegisterStatsd(metricsConfig.StatsD))
		log.Debugf("Configured StatsD metrics pushing to %s once every %s", metricsConfig.StatsD.Address, metricsConfig.StatsD.PushInterval)
	}
	if metricsConfig.InfluxDB != nil {
		registries = append(registries, metrics.RegisterInfluxDB(metricsConfig.InfluxDB))
		log.Debugf("Configured InfluxDB metrics pushing to %s once every %s", metricsConfig.InfluxDB.Address, metricsConfig.InfluxDB.PushInterval)
	}

	return metrics.NewMultiRegistry(registries)
}

func stopMetricsClients() {
	metrics.StopDatadog()
	metrics.StopStatsd()
	metrics.StopInfluxDB()
}

func (s *Server) buildNameOrIPToCertificate(certs []tls.Certificate) map[string]*tls.Certificate {
	certMap := make(map[string]*tls.Certificate)
	for i := range certs {
		cert := &certs[i]
		x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			continue
		}
		if len(x509Cert.Subject.CommonName) > 0 {
			certMap[x509Cert.Subject.CommonName] = cert
		}
		for _, san := range x509Cert.DNSNames {
			certMap[san] = cert
		}
		for _, ipSan := range x509Cert.IPAddresses {
			certMap[ipSan.String()] = cert
		}
	}
	return certMap
}
