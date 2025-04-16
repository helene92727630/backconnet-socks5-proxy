package main

import (
	"bufio"
	// "context" // No longer needed for API
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	// "html/template" // No longer needed for API
	"io"
	"log"
	"math/rand"
	"net"
	// "net/http" // No longer needed for API
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	// Consider adding a proper SOCKS5 client library for upstream connections later
	// "golang.org/x/net/proxy"
)

// --- Настройки ---
const (
	proxyFile             = "socks5_proxies.txt" // File for upstream proxies
	checkTimeout          = 5 * time.Second      // Timeout for checking upstream proxies
	defaultServerPort     = 8080                 // Default Port for the SOCKS5 server
	defaultListenAddress  = "0.0.0.0"
	// defaultAPIPort        = 8082 // Removed API Port
	usersFile             = "users.json"         // File for SOCKS5 user credentials
	whitelistFile         = "whitelist.txt"
	defaultRotationInterval = 5 * time.Minute      // Interval for checking upstream proxies
	socksReadTimeout      = 15 * time.Second     // Increased timeout for reading SOCKS protocol steps (client and upstream)
	upstreamDialTimeout   = 10 * time.Second     // Timeout for dialing upstream proxy
	upstreamMaxRetries    = 3                    // Max attempts to connect to different upstream proxies
)

var (
	userCredentials = map[string]userConfig{} // SOCKS5 user credentials from users.json

	whitelist       = []string{} // Whitelist for allowed client IPs from whitelist.txt

	// Upstream proxy list
	allProxies       []proxyEntry
	workingProxies   []proxyEntry // List of currently working upstream proxies
	mu               sync.RWMutex // Protects userCredentials, whitelist, workingProxies
	adminUsername    = "admin"    // Default admin username (used for check in deleteUser)
	serverPort       int        // Port for the SOCKS5 server itself
	// apiPort          int      // Removed API Port
	listenAddress    string
	// templateCache *template.Template // Removed template cache
	rotationInterval time.Duration = defaultRotationInterval
)

// --- SOCKS5 Constants ---
const (
	socks5Version         byte = 0x05 // Use byte type for constants used as bytes
	socks5AuthNone        byte = 0x00
	socks5AuthUserPass    byte = 0x02
	socks5AuthNoAcceptable byte = 0xFF
	socks5UserPassVersion byte = 0x01 // Version for username/password auth subnegotiation
	socks5UserPassStatusSuccess byte = 0x00
	socks5UserPassStatusFailure byte = 0x01 // General failure
	socks5CmdConnect      byte = 0x01
	socks5CmdBind         byte = 0x02 // Not implemented
	socks5CmdUDP          byte = 0x03 // Not implemented
	socks5Reserved        byte = 0x00
	socks5AddrTypeIPv4    byte = 0x01
	socks5AddrTypeDomain  byte = 0x03
	socks5AddrTypeIPv6    byte = 0x04
	socks5ReplySuccess    byte = 0x00
	socks5ReplyGenFail    byte = 0x01
	socks5ReplyRuleFail   byte = 0x02 // Not used currently
	socks5ReplyNetUnreach byte = 0x03
	socks5ReplyHostUnreach byte = 0x04
	socks5ReplyConnRefused byte = 0x05
	socks5ReplyTTLExpired byte = 0x06 // Not used currently
	socks5ReplyCmdNotSupp byte = 0x07
	socks5ReplyAddrNotSupp byte = 0x08
)

// --- Типы ---

// proxyEntry представляет собой запись прокси с адресом и учетными данными.
type proxyEntry struct {
	Address  string `json:"Address"`
	Username string `json:"Username,omitempty"`
	Password string `json:"Password,omitempty"`
}

// usersData is a type alias for the map storing user configurations.
type usersData map[string]userConfig

// userConfig stores the password hash and rotation interval for a user.
type userConfig struct {
	Password         string // Stores the bcrypt hash of the password
	RotationInterval time.Duration // Currently unused by SOCKS5 server logic
}

// --- Функции ---

// loadProxies загружает прокси из файла.
func loadProxies(filePath string) ([]proxyEntry, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("error opening proxy file %s: %w", filePath, err)
	}
	defer file.Close()

	var proxies []proxyEntry
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") { // Skip empty lines and comments
			continue
		}

		parts := strings.SplitN(line, "@", 2)
		var address, username, password string

		if len(parts) == 2 {
			// Credentials are present
			authParts := strings.SplitN(parts[0], ":", 2)
			if len(authParts) != 2 {
				log.Printf("Invalid proxy format (credentials): %s", line)
				continue // Skip invalid format
			}
			username = authParts[0]
			password = authParts[1]
			address = parts[1]
		} else {
			// No credentials
			address = parts[0]
		}

		// Basic validation for address (should contain ':')
		if !strings.Contains(address, ":") {
			log.Printf("Invalid proxy format (address without port?): %s", line)
			continue
		}

		proxies = append(proxies, proxyEntry{Address: address, Username: username, Password: password})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning proxy file %s: %w", filePath, err)
	}
	log.Printf("Loaded %d upstream proxy entries from %s", len(proxies), filePath)
	return proxies, nil
}

// checkProxy проверяет доступность SOCKS5 прокси.
func checkProxy(proxy proxyEntry) bool {
	conn, err := net.DialTimeout("tcp", proxy.Address, checkTimeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	// TODO: Optionally implement a basic SOCKS5 handshake check here
	// to verify it's actually a SOCKS5 proxy, not just a TCP port.
	return true
}

// getWorkingProxies проверяет список прокси и возвращает только рабочие.
func getWorkingProxies(proxies []proxyEntry) []proxyEntry {
	var wg sync.WaitGroup
	var working []proxyEntry
	var workingMu sync.Mutex

	numWorkers := 50
	if len(proxies) < numWorkers {
		numWorkers = len(proxies)
	}
	proxyChan := make(chan proxyEntry, len(proxies))
	resultsChan := make(chan proxyEntry, len(proxies))

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range proxyChan {
				if checkProxy(p) {
					resultsChan <- p
				}
			}
		}()
	}

	for _, proxy := range proxies {
		proxyChan <- proxy
	}
	close(proxyChan)

	collectionDone := make(chan struct{})
	go func() {
		for p := range resultsChan {
			workingMu.Lock()
			working = append(working, p)
			workingMu.Unlock()
		}
		close(collectionDone)
	}()

	wg.Wait()
	close(resultsChan)
	<-collectionDone

	return working
}


// isWhitelisted проверяет, находится ли IP-адрес клиента в белом списке.
func isWhitelisted(ip string) bool {
	clientIP := net.ParseIP(ip)
	if clientIP == nil {
		log.Printf("Invalid client IP address for whitelist check: %s", ip)
		return false // Cannot parse IP, deny access
	}

	mu.RLock() // Lock for reading the whitelist
	defer mu.RUnlock()

	for _, cidr := range whitelist {
		if strings.Contains(cidr, "/") {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				log.Printf("Error parsing CIDR %s in whitelist: %v", cidr, err)
				continue // Skip invalid CIDR entry
			}
			if network.Contains(clientIP) {
				return true
			}
		} else {
			// Treat as a single IP address
			whitelistIP := net.ParseIP(cidr)
			if whitelistIP != nil && whitelistIP.Equal(clientIP) {
				return true
			}
		}
	}
	return false
}

// --- SOCKS5 Server Logic ---

// handleSocksConnection handles a new connection assuming it's a SOCKS5 client.
// Routes traffic through an upstream proxy.
// Allows whitelisted IPs without auth, otherwise requires user/pass auth.
// Implements retry logic for initial upstream connection/handshake.
func handleSocksConnection(clientConn net.Conn) {
	clientRemoteAddr := clientConn.RemoteAddr().String()
	log.Printf("SOCKS: Accepted connection from %s", clientRemoteAddr)
	defer func() {
		log.Printf("SOCKS: Closing connection from %s", clientRemoteAddr)
		clientConn.Close()
	}()

	// 1. Whitelist Check (Store result, don't deny yet)
	clientIP, _, err := net.SplitHostPort(clientRemoteAddr)
	if err != nil {
		log.Printf("SOCKS: Error getting client IP from %s: %v", clientRemoteAddr, err)
		return
	}
	isClientWhitelisted := isWhitelisted(clientIP)
	if isClientWhitelisted {
		log.Printf("SOCKS: Client IP %s is in whitelist.", clientIP)
	} else {
		log.Printf("SOCKS: Client IP %s is NOT in whitelist.", clientIP)
	}

	// Use bufio.Reader for easier byte reading from client
	clientReader := bufio.NewReader(clientConn)

	// Set initial deadlines for protocol steps with client
	clientConn.SetReadDeadline(time.Now().Add(socksReadTimeout))
	defer clientConn.SetReadDeadline(time.Time{}) // Clear deadline upon exit

	// 2. Client Version and Auth Method Negotiation (RFC 1928 Section 3)
	// Read version identifier (must be 0x05)
	versionByte, err := clientReader.ReadByte() // Read version from client
	if err != nil {
		log.Printf("SOCKS: Error reading version byte from %s: %v", clientRemoteAddr, err)
		return
	}
	if versionByte != socks5Version {
		log.Printf("SOCKS: Denied connection from %s: Unsupported SOCKS version %x", clientRemoteAddr, versionByte)
		return
	}

	// Handle Auth Negotiation based on whitelist status
	needsUserPassAuth, err := handleClientAuthNegotiation(clientConn, clientReader, isClientWhitelisted)
	if err != nil {
		log.Printf("SOCKS: Client auth negotiation failed for %s: %v", clientRemoteAddr, err)
		// Error response already sent by handleClientAuthNegotiation
		return
	}

	// 3. Client Username/Password Authentication (RFC 1929) - If Required
	username := "whitelisted_or_noauth" // Default username if auth skipped
	if needsUserPassAuth {
		var authErr error
		username, authErr = handleClientUserPassAuth(clientConn, clientReader) // Overwrite username if auth happens
		if authErr != nil {
			log.Printf("SOCKS: Client authentication failed for %s: %v", clientRemoteAddr, authErr)
			// Error response already sent by handleClientUserPassAuth
			return
		}
		// If handleClientUserPassAuth succeeded, username is now set correctly
	} else {
		log.Printf("SOCKS: Skipping Username/Password auth for %s (whitelisted or No Auth selected)", clientRemoteAddr)
	}

	// 4. Client Request Processing (RFC 1928 Section 4 & 5)
	// Use _ for addrType as it's not needed later in this function
	cmd, _, destAddr, destPort, rawDestBytes, err := handleClientRequest(clientConn, clientReader)
	if err != nil {
		log.Printf("SOCKS: Client request processing failed for %s (user: %s): %v", clientRemoteAddr, username, err)
		// Error reply sent by handleClientRequest
		return
	}
	if cmd != socks5CmdConnect {
		log.Printf("SOCKS: Unsupported command %x from %s (user: %s)", cmd, clientRemoteAddr, username)
		sendSocksErrorReply(clientConn, socks5ReplyCmdNotSupp, nil)
		return
	}
	destHostPort := net.JoinHostPort(destAddr, strconv.Itoa(int(destPort)))
	log.Printf("SOCKS: User '%s' requests CONNECT to %s", username, destHostPort)

	// --- Upstream Connection with Retry Logic ---
	var upstreamConn net.Conn = nil // Holds the successful upstream connection
	var lastUpstreamError error = errors.New("no working upstream proxies available") // Store the last error

	// Get a shuffled list of working proxies to try
	mu.RLock()
	availableProxies := make([]proxyEntry, len(workingProxies))
	copy(availableProxies, workingProxies)
	mu.RUnlock()

	if len(availableProxies) == 0 {
		log.Printf("SOCKS: No working upstream proxies available for %s (user: %s)", clientRemoteAddr, username)
		sendSocksErrorReply(clientConn, socks5ReplyGenFail, nil)
		return
	}

	// Shuffle the copied list
	rand.Shuffle(len(availableProxies), func(i, j int) {
		availableProxies[i], availableProxies[j] = availableProxies[j], availableProxies[i]
	})

	// Determine how many proxies to try (up to maxRetries or total available)
	retries := upstreamMaxRetries
	if len(availableProxies) < retries {
		retries = len(availableProxies)
	}

	// Clear deadline before potentially long-running retries
	clientConn.SetReadDeadline(time.Time{})

	for i := 0; i < retries; i++ {
		selectedProxy := availableProxies[i]
		log.Printf("SOCKS: Attempt %d/%d: Routing %s (user: %s) via upstream proxy %s", i+1, retries, clientRemoteAddr, username, selectedProxy.Address)

		// 5. Connect to Upstream Proxy
		currentUpstreamConn, dialErr := net.DialTimeout("tcp", selectedProxy.Address, upstreamDialTimeout)
		if dialErr != nil {
			log.Printf("SOCKS: Attempt %d/%d: Failed to connect to upstream proxy %s: %v", i+1, retries, selectedProxy.Address, dialErr)
			lastUpstreamError = dialErr // Update last error
			continue // Try next proxy
		}
		log.Printf("SOCKS: Attempt %d/%d: Connected to upstream proxy %s", i+1, retries, selectedProxy.Address)

		// 6. Perform SOCKS5 Handshake with Upstream Proxy
		upstreamRW := bufio.NewReadWriter(bufio.NewReader(currentUpstreamConn), bufio.NewWriter(currentUpstreamConn))
		currentUpstreamConn.SetDeadline(time.Now().Add(socksReadTimeout)) // Deadline for this attempt's handshake

		// FIX: Discard upstreamReplyCode using blank identifier '_' as it's not used here
		_, handshakeErr := performUpstreamSocksHandshake(upstreamRW, selectedProxy, cmd, rawDestBytes)
		currentUpstreamConn.SetDeadline(time.Time{}) // Clear deadline after handshake attempt

		if handshakeErr != nil {
			log.Printf("SOCKS: Attempt %d/%d: Handshake with upstream proxy %s failed: %v", i+1, retries, selectedProxy.Address, handshakeErr)
			lastUpstreamError = handshakeErr // Update last error
			currentUpstreamConn.Close()      // Close this failed connection
			continue // Try next proxy
		}

		// Success! Store the connection and break the loop
		log.Printf("SOCKS: Attempt %d/%d: Successfully established connection via upstream proxy %s", i+1, retries, selectedProxy.Address)
		upstreamConn = currentUpstreamConn // Assign the successful connection
		lastUpstreamError = nil             // Reset error on success
		break
	} // End of retry loop

	// Check if all retries failed
	if upstreamConn == nil {
		log.Printf("SOCKS: All %d upstream connection attempts failed for %s (user: %s). Last error: %v", retries, clientRemoteAddr, username, lastUpstreamError)
		// Send appropriate error based on the last error encountered
		var replyCode byte = socks5ReplyGenFail // Default
		if strings.Contains(lastUpstreamError.Error(), "refused") {
			replyCode = socks5ReplyConnRefused
		} else if strings.Contains(lastUpstreamError.Error(), "no such host") || strings.Contains(lastUpstreamError.Error(), "timeout") || strings.Contains(lastUpstreamError.Error(), "i/o timeout") {
			// Treat dial timeout/host unreachable as host unreachable
			replyCode = socks5ReplyHostUnreach
		} else if strings.Contains(lastUpstreamError.Error(), "network is unreachable") {
			replyCode = socks5ReplyNetUnreach
		}
		sendSocksErrorReply(clientConn, replyCode, nil)
		return
	}

	// --- Connection Established via Upstream Proxy ---
	defer upstreamConn.Close() // Ensure the successful connection is closed eventually

	// 7. Send Success Reply to Original Client
	log.Printf("SOCKS: Upstream proxy %s successfully connected to %s for %s (user: %s)", upstreamConn.RemoteAddr(), destHostPort, clientRemoteAddr, username) // Log actual upstream conn addr
	// Send success reply, BND.ADDR/PORT can be 0.0.0.0:0
	bindAddrBytes := []byte{0x00, 0x00, 0x00, 0x00}
	bindPortBytes := []byte{0x00, 0x00}
	reply := append([]byte{socks5Version, socks5ReplySuccess, socks5Reserved, socks5AddrTypeIPv4}, bindAddrBytes...)
	reply = append(reply, bindPortBytes...)
	_, err = clientConn.Write(reply)
	if err != nil {
		log.Printf("SOCKS: Error sending success reply to %s (user: %s): %v", clientRemoteAddr, username, err)
		return
	}

	// 8. Tunnel Data between client and the successful upstream connection
	log.Printf("SOCKS: Starting data tunnel between %s (user: %s) and upstream %s (-> %s)", clientRemoteAddr, username, upstreamConn.RemoteAddr(), destHostPort)
	errChan := make(chan error, 2)

	copyData := func(dst io.WriteCloser, src io.Reader, desc string) {
		defer dst.Close() // Close writer when done
		bytesCopied, err := io.Copy(dst, src)
		log.Printf("SOCKS: Copied %d bytes %s", bytesCopied, desc)
		errChan <- err
	}

	// Need to use the ReadWriter for the upstream connection if created, otherwise the raw conn
	// Let's re-create the ReadWriter here for clarity, using the final successful upstreamConn
	finalUpstreamRW := bufio.NewReadWriter(bufio.NewReader(upstreamConn), bufio.NewWriter(upstreamConn))

	go copyData(upstreamConn, clientReader, fmt.Sprintf("from client %s to upstream %s", clientRemoteAddr, upstreamConn.RemoteAddr()))
	go copyData(clientConn, finalUpstreamRW.Reader, fmt.Sprintf("from upstream %s to client %s", upstreamConn.RemoteAddr(), clientRemoteAddr))

	// Wait for tunnel goroutines
	for i := 0; i < 2; i++ {
		if err := <-errChan; err != nil {
			// Don't log EOF or closed connection errors as errors, they are expected ways to finish
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) && !strings.Contains(err.Error(), "use of closed network connection") {
				log.Printf("SOCKS: Error during data tunnel for %s (user: %s): %v", clientRemoteAddr, username, err)
			}
		}
	}
	log.Printf("SOCKS: Data tunnel finished for %s (user: %s)", clientRemoteAddr, username)
}


// handleClientAuthNegotiation performs SOCKS5 version and auth method negotiation with the client.
// It considers the whitelist status. Returns true if User/Pass auth is needed next.
func handleClientAuthNegotiation(conn net.Conn, reader *bufio.Reader, isWhitelisted bool) (needsUserPassAuth bool, err error) {
	// Read number of methods
	nMethods, err := reader.ReadByte()
	if err != nil {
		return false, fmt.Errorf("reading nmethods failed: %w", err)
	}
	if nMethods == 0 {
		return false, errors.New("client offered no authentication methods")
	}
	// Read methods
	methods := make([]byte, nMethods)
	_, err = io.ReadFull(reader, methods)
	if err != nil {
		return false, fmt.Errorf("reading methods failed: %w", err)
	}

	// Check available methods
	clientSupportsNoAuth := false
	clientSupportsUserPass := false
	for _, method := range methods {
		if method == socks5AuthNone {
			clientSupportsNoAuth = true
		}
		if method == socks5AuthUserPass {
			clientSupportsUserPass = true
		}
	}

	// Decide which method to select based on whitelist status
	if isWhitelisted && clientSupportsNoAuth {
		// Whitelisted client supports No Auth - select it
		log.Printf("SOCKS: Selecting No Authentication (0x00) for whitelisted client %s", conn.RemoteAddr())
		_, err = conn.Write([]byte{socks5Version, socks5AuthNone})
		if err != nil {
			return false, fmt.Errorf("sending No Auth selection failed: %w", err)
		}
		return false, nil // No User/Pass needed
	} else if clientSupportsUserPass {
		// Either client is not whitelisted, or is whitelisted but doesn't support No Auth
		// Select User/Pass if supported
		log.Printf("SOCKS: Selecting Username/Password (0x02) for client %s (Whitelisted: %t)", conn.RemoteAddr(), isWhitelisted)
		_, err = conn.Write([]byte{socks5Version, socks5AuthUserPass})
		if err != nil {
			return false, fmt.Errorf("sending User/Pass selection failed: %w", err)
		}
		return true, nil // User/Pass needed
	} else {
		// Client doesn't support User/Pass, and if whitelisted, didn't support No Auth either
		log.Printf("SOCKS: No acceptable authentication method found for client %s (Whitelisted: %t, Supports NoAuth: %t, Supports UserPass: %t)",
			conn.RemoteAddr(), isWhitelisted, clientSupportsNoAuth, clientSupportsUserPass)
		_, wErr := conn.Write([]byte{socks5Version, socks5AuthNoAcceptable})
		if wErr != nil {
			log.Printf("SOCKS: Error sending auth failure to %s: %v", conn.RemoteAddr(), wErr)
		}
		return false, errors.New("no acceptable authentication method found")
	}
}


// handleClientUserPassAuth performs SOCKS5 username/password authentication with the client.
// Returns the authenticated username or an error.
func handleClientUserPassAuth(conn net.Conn, reader *bufio.Reader) (string, error) {
	// Read User/Pass request version
	authVersion, err := reader.ReadByte()
	if err != nil {
		return "", fmt.Errorf("reading auth version failed: %w", err)
	}
	if authVersion != socks5UserPassVersion {
		return "", fmt.Errorf("unsupported auth subnegotiation version %x", authVersion)
	}
	// Read ULEN
	uLen, err := reader.ReadByte()
	if err != nil || uLen == 0 {
		return "", fmt.Errorf("reading/invalid username length failed: %w", err)
	}
	// Read Username
	usernameBytes := make([]byte, uLen)
	_, err = io.ReadFull(reader, usernameBytes)
	if err != nil {
		return "", fmt.Errorf("reading username failed: %w", err)
	}
	username := string(usernameBytes)
	// Read PLEN
	pLen, err := reader.ReadByte()
	if err != nil || pLen == 0 {
		return "", fmt.Errorf("reading/invalid password length failed: %w", err)
	}
	// Read Password
	passwordBytes := make([]byte, pLen)
	_, err = io.ReadFull(reader, passwordBytes)
	if err != nil {
		return "", fmt.Errorf("reading password failed: %w", err)
	}
	password := string(passwordBytes)

	// Verify credentials
	mu.RLock()
	userConf, userExists := userCredentials[username]
	mu.RUnlock()

	authSuccess := false
	if userExists {
		err = bcrypt.CompareHashAndPassword([]byte(userConf.Password), []byte(password))
		if err == nil {
			authSuccess = true
		} else if !errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
			log.Printf("SOCKS: Internal error comparing password hash for user '%s': %v", username, err)
			// Treat internal error as auth failure for safety
		}
	}

	// Send Auth Response
	var authStatus byte = socks5UserPassStatusFailure // Declare as byte
	if authSuccess {
		authStatus = socks5UserPassStatusSuccess
	}
	_, err = conn.Write([]byte{socks5UserPassVersion, authStatus}) // Use byte variable authStatus
	if err != nil {
		// If we can't even send the status, the connection is likely broken
		return username, fmt.Errorf("sending auth status failed: %w", err)
	}
	if !authSuccess {
		return username, errors.New("invalid credentials")
	}
	// Don't log success here, log it in the main handler after all steps succeed
	// log.Printf("SOCKS: User '%s' authenticated successfully from %s", username, conn.RemoteAddr())
	return username, nil
}

// handleClientRequest reads the SOCKS5 request (command, address, port) from the client.
// Returns parsed info and the raw address+port bytes for forwarding.
func handleClientRequest(conn net.Conn, reader *bufio.Reader) (cmd, addrType byte, destAddr string, destPort uint16, rawDestBytes []byte, err error) {
	// Read request header: Version, Command, Reserved
	reqHeader := make([]byte, 3)
	_, err = io.ReadFull(reader, reqHeader)
	if err != nil {
		err = fmt.Errorf("reading request header failed: %w", err)
		sendSocksErrorReply(conn, socks5ReplyGenFail, nil)
		return
	}
	if reqHeader[0] != socks5Version {
		err = fmt.Errorf("invalid SOCKS version in request: %x", reqHeader[0])
		sendSocksErrorReply(conn, socks5ReplyGenFail, nil)
		return
	}
	if reqHeader[2] != socks5Reserved {
		err = fmt.Errorf("invalid reserved byte in request: %x", reqHeader[2])
		sendSocksErrorReply(conn, socks5ReplyGenFail, nil)
		return
	}
	cmd = reqHeader[1]

	// Read Address Type (ATYP)
	addrType, err = reader.ReadByte()
	if err != nil {
		err = fmt.Errorf("reading address type failed: %w", err)
		sendSocksErrorReply(conn, socks5ReplyGenFail, nil)
		return
	}

	// Read Destination Address based on ATYP
	rawDestBytes = append(rawDestBytes, addrType) // Start raw bytes with ATYP

	switch addrType {
	case socks5AddrTypeIPv4:
		ipv4Bytes := make([]byte, 4)
		_, err = io.ReadFull(reader, ipv4Bytes)
		if err != nil {
			err = fmt.Errorf("reading IPv4 address failed: %w", err)
			sendSocksErrorReply(conn, socks5ReplyGenFail, nil)
			return
		}
		destAddr = net.IP(ipv4Bytes).String()
		rawDestBytes = append(rawDestBytes, ipv4Bytes...)
	case socks5AddrTypeDomain:
		var domainLenByte byte
		domainLenByte, err = reader.ReadByte() // Read length first
		if err != nil || domainLenByte == 0 {
			err = fmt.Errorf("reading/invalid domain length failed: %w", err)
			sendSocksErrorReply(conn, socks5ReplyGenFail, nil)
			return
		}
		domainBytes := make([]byte, domainLenByte)
		_, err = io.ReadFull(reader, domainBytes)
		if err != nil {
			err = fmt.Errorf("reading domain name failed: %w", err)
			sendSocksErrorReply(conn, socks5ReplyGenFail, nil)
			return
		}
		destAddr = string(domainBytes)
		rawDestBytes = append(rawDestBytes, domainLenByte) // Append length byte
		rawDestBytes = append(rawDestBytes, domainBytes...) // Append domain bytes
	case socks5AddrTypeIPv6:
		ipv6Bytes := make([]byte, 16)
		_, err = io.ReadFull(reader, ipv6Bytes)
		if err != nil {
			err = fmt.Errorf("reading IPv6 address failed: %w", err)
			sendSocksErrorReply(conn, socks5ReplyGenFail, nil)
			return
		}
		destAddr = net.IP(ipv6Bytes).String()
		rawDestBytes = append(rawDestBytes, ipv6Bytes...)
	default:
		err = fmt.Errorf("unsupported address type %x", addrType)
		sendSocksErrorReply(conn, socks5ReplyAddrNotSupp, nil)
		return
	}

	// Read Destination Port
	portBytes := make([]byte, 2)
	_, err = io.ReadFull(reader, portBytes)
	if err != nil {
		err = fmt.Errorf("reading port failed: %w", err)
		sendSocksErrorReply(conn, socks5ReplyGenFail, nil)
		return
	}
	destPort = binary.BigEndian.Uint16(portBytes)
	rawDestBytes = append(rawDestBytes, portBytes...)

	return // Return successfully parsed values
}

// performUpstreamSocksHandshake connects to the upstream proxy and performs handshake/command.
// Returns the SOCKS reply code from the upstream proxy or an error.
func performUpstreamSocksHandshake(upstreamRW *bufio.ReadWriter, proxy proxyEntry, clientCmd byte, rawClientDestBytes []byte) (byte, error) {
	// 1. Upstream Auth Negotiation
	var methodsToOffer []byte
	if proxy.Username != "" && proxy.Password != "" {
		methodsToOffer = []byte{socks5AuthUserPass, socks5AuthNone} // Offer User/Pass first if available
	} else {
		methodsToOffer = []byte{socks5AuthNone} // Offer only No Auth
	}
	// Send initial handshake: [Version, NMethods, Methods...]
	handshake := append([]byte{socks5Version, byte(len(methodsToOffer))}, methodsToOffer...)
	_, err := upstreamRW.Write(handshake)
	if err != nil {
		return socks5ReplyGenFail, fmt.Errorf("sending handshake to upstream failed: %w", err)
	}
	err = upstreamRW.Flush()
	if err != nil {
		return socks5ReplyGenFail, fmt.Errorf("flushing handshake to upstream failed: %w", err)
	}

	// Read upstream response: [Version, Method]
	resp := make([]byte, 2)
	_, err = io.ReadFull(upstreamRW.Reader, resp)
	if err != nil {
		return socks5ReplyGenFail, fmt.Errorf("reading upstream auth method choice failed: %w", err)
	}
	if resp[0] != socks5Version {
		return socks5ReplyGenFail, fmt.Errorf("upstream sent invalid version %x", resp[0])
	}

	// 2. Upstream Authentication (if needed)
	switch resp[1] {
	case socks5AuthNone:
		log.Printf("SOCKS: Upstream %s accepted No Authentication", proxy.Address)
		// Proceed
	case socks5AuthUserPass:
		if proxy.Username == "" || proxy.Password == "" {
			return socks5ReplyGenFail, fmt.Errorf("upstream %s requires User/Pass auth, but no credentials provided", proxy.Address)
		}
		log.Printf("SOCKS: Upstream %s requires User/Pass Authentication", proxy.Address)
		// Send User/Pass subnegotiation request: [Version, ULEN, UNAME, PLEN, PASSWD]
		uLen := byte(len(proxy.Username))
		pLen := byte(len(proxy.Password))
		authReq := make([]byte, 0, 1+1+uLen+1+pLen)
		authReq = append(authReq, socks5UserPassVersion)
		authReq = append(authReq, uLen)
		authReq = append(authReq, []byte(proxy.Username)...)
		authReq = append(authReq, pLen)
		authReq = append(authReq, []byte(proxy.Password)...)

		_, err = upstreamRW.Write(authReq)
		if err != nil {
			return socks5ReplyGenFail, fmt.Errorf("sending upstream auth request failed: %w", err)
		}
		err = upstreamRW.Flush()
		if err != nil {
			return socks5ReplyGenFail, fmt.Errorf("flushing upstream auth request failed: %w", err)
		}

		// Read upstream auth response: [Version, Status]
		authResp := make([]byte, 2)
		_, err = io.ReadFull(upstreamRW.Reader, authResp)
		if err != nil {
			return socks5ReplyGenFail, fmt.Errorf("reading upstream auth response failed: %w", err)
		}
		if authResp[0] != socks5UserPassVersion {
			return socks5ReplyGenFail, fmt.Errorf("upstream sent invalid auth response version %x", authResp[0])
		}
		if authResp[1] != socks5UserPassStatusSuccess {
			return socks5ReplyGenFail, fmt.Errorf("upstream authentication failed with status %x", authResp[1])
		}
		log.Printf("SOCKS: Successfully authenticated with upstream %s (user: %s)", proxy.Address, proxy.Username)
	default:
		return socks5ReplyGenFail, fmt.Errorf("upstream %s selected unsupported auth method %x", proxy.Address, resp[1])
	}

	// 3. Send Client's Request to Upstream
	// [Version, CMD, RSV, ATYP, DST.ADDR, DST.PORT]
	// rawClientDestBytes already contains [ATYP, DST.ADDR, DST.PORT]
	upstreamReq := append([]byte{socks5Version, clientCmd, socks5Reserved}, rawClientDestBytes...)
	_, err = upstreamRW.Write(upstreamReq)
	if err != nil {
		return socks5ReplyGenFail, fmt.Errorf("sending command to upstream failed: %w", err)
	}
	err = upstreamRW.Flush()
	if err != nil {
		return socks5ReplyGenFail, fmt.Errorf("flushing command to upstream failed: %w", err)
	}

	// 4. Read Reply from Upstream
	// Read header: Version, Reply, Reserved, AddrType
	replyHeader := make([]byte, 4)
	_, err = io.ReadFull(upstreamRW.Reader, replyHeader)
	if err != nil {
		// If upstream closes connection here, it might indicate connection refused to target
		if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "reset by peer") {
			log.Printf("SOCKS: Connection closed by upstream %s after sending command (possible target connection failure)", proxy.Address)
			return socks5ReplyConnRefused, fmt.Errorf("connection closed by upstream after command: %w", err) // Assume connection refused
		}
		return socks5ReplyGenFail, fmt.Errorf("reading upstream reply header failed: %w", err)
	}
	if replyHeader[0] != socks5Version {
		return socks5ReplyGenFail, fmt.Errorf("upstream sent invalid reply version %x", replyHeader[0])
	}
	upstreamReplyCode := replyHeader[1]
	if upstreamReplyCode != socks5ReplySuccess {
		// Read rest of address/port even on failure to consume data
		// but return the failure code
		_, errConsume := readSocksAddress(upstreamRW.Reader, replyHeader[3])
		if errConsume != nil {
			log.Printf("SOCKS: Error consuming address data after upstream failure reply %x: %v", upstreamReplyCode, errConsume)
		}
		return upstreamReplyCode, fmt.Errorf("upstream proxy command failed with code %x", upstreamReplyCode)
	}

	// Read and discard Bind Address/Port from upstream reply
	_, err = readSocksAddress(upstreamRW.Reader, replyHeader[3])
	if err != nil {
		return socks5ReplyGenFail, fmt.Errorf("reading upstream bind address failed: %w", err)
	}

	// Upstream connection successful
	return socks5ReplySuccess, nil
}

// readSocksAddress reads a SOCKS5 address (based on ATYP) and port.
// Used to consume the address/port fields from replies.
func readSocksAddress(reader io.Reader, addrType byte) ([]byte, error) {
	var addrLen int
	switch addrType {
	case socks5AddrTypeIPv4:
		addrLen = 4
	case socks5AddrTypeDomain:
		lenByte := make([]byte, 1)
		_, err := io.ReadFull(reader, lenByte) // Use io.ReadFull
		if err != nil {
			return nil, fmt.Errorf("reading domain length byte failed: %w", err)
		}
		domainLen := lenByte[0] // Get the actual byte value
		if domainLen == 0 {
			return nil, errors.New("invalid domain length received (zero)")
		}
		addrLen = int(domainLen)
		// We need to return the length byte as part of the address field for domain type
		addrBytes := make([]byte, 1+addrLen)
		addrBytes[0] = domainLen // Store length byte
		_, err = io.ReadFull(reader, addrBytes[1:]) // Read domain into rest of slice
		if err != nil {
			return nil, fmt.Errorf("reading domain name failed: %w", err)
		}
		// Read port separately
		portBytes := make([]byte, 2)
		_, err = io.ReadFull(reader, portBytes)
		if err != nil {
			return nil, fmt.Errorf("reading port after domain failed: %w", err)
		}
		return append(addrBytes, portBytes...), nil // Return domain len + domain + port
	case socks5AddrTypeIPv6:
		addrLen = 16
	default:
		return nil, fmt.Errorf("unsupported address type %x in reply", addrType)
	}

	// For IPv4 and IPv6
	addrBytes := make([]byte, addrLen)
	_, err := io.ReadFull(reader, addrBytes)
	if err != nil {
		return nil, fmt.Errorf("reading address bytes failed: %w", err)
	}

	// Read port (2 bytes)
	portBytes := make([]byte, 2)
	_, err = io.ReadFull(reader, portBytes)
	if err != nil {
		return nil, fmt.Errorf("reading port failed: %w", err)
	}

	return append(addrBytes, portBytes...), nil
}


// sendSocksErrorReply sends a SOCKS5 error reply back to the client.
// BND address/port are typically zeroed out for errors.
func sendSocksErrorReply(conn net.Conn, replyCode byte, bindAddr net.IP) { // Ensure replyCode is byte
	reply := []byte{
		socks5Version,
		replyCode, // Use byte directly
		socks5Reserved,
		socks5AddrTypeIPv4, // Default to IPv4 address type for bind addr
		0x00, 0x00, 0x00, 0x00, // 0.0.0.0
		0x00, 0x00, // Port 0
	}
	// If a specific bind address was provided (e.g., IPv6), adjust ATYP and address bytes
	// For simplicity, we always send back 0.0.0.0:0 on error currently.

	_, err := conn.Write(reply)
	if err != nil {
		log.Printf("SOCKS: Error sending error reply (%x) to client %s: %v", replyCode, conn.RemoteAddr(), err)
	}
}

// --- Функции для работы с файлами и пользователями --- (ADDED BACK)

// хеширует пароль с использованием bcrypt
func hashPassword(password string) (string, error) {
	// Check password length before hashing
	if len(password) == 0 {
		return "", fmt.Errorf("password cannot be empty")
	}
	if len(password) > 72 {
		// bcrypt has a maximum password length of 72 bytes
		log.Printf("Warning: Password provided is longer than 72 bytes and will be truncated by bcrypt.")
		// return "", fmt.Errorf("password is too long (max 72 bytes)") // Or truncate silently
	}
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("failed to hash password: %w", err)
	}
	return string(hashedPassword), nil
}


// loadUsersFromFile загружает данные пользователей из users.json.
func loadUsersFromFile() (usersData, error) {
	file, err := os.Open(usersFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Users file '%s' not found, starting with empty user list.", usersFile)
			return make(usersData), nil // Если файл не существует, возвращаем пустую карту
		}
		return nil, fmt.Errorf("error opening users file %s: %w", usersFile, err)
	}
	defer file.Close()

	data := make(usersData)
	decoder := json.NewDecoder(file)
	err = decoder.Decode(&data)
	// Allow empty file (EOF is not an error in this case for an empty JSON object {})
	if err != nil && err != io.EOF {
		// Check for empty file specifically
		stat, statErr := file.Stat()
		if statErr == nil && stat.Size() == 0 {
			log.Printf("Users file '%s' is empty, starting with empty user list.", usersFile)
			return make(usersData), nil // Treat empty file same as non-existent
		}
		return nil, fmt.Errorf("error decoding users file %s: %w", usersFile, err)
	}

	// Ensure default rotation interval is set if missing or zero
	updated := false
	for name, config := range data {
		if config.RotationInterval <= 0 {
			config.RotationInterval = defaultRotationInterval
			data[name] = config
			if !updated { // Log only once if updates happen
				log.Printf("Setting default rotation interval (%s) for users with missing/zero interval in %s", defaultRotationInterval, usersFile)
				updated = true
			}
		}
	}
	log.Printf("Loaded %d SOCKS users from %s", len(data), usersFile)
	return data, nil
}

// saveUsersToFileLocked сохраняет данные пользователей в users.json. Assumes lock is held.
func saveUsersToFileLocked() error {
	// Create a temporary file first in the same directory
	tempFile := usersFile + ".tmp"
	file, err := os.Create(tempFile)
	if err != nil {
		return fmt.Errorf("could not create temporary users file %s: %w", tempFile, err)
	}
	// No defer, explicitly close before rename

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ") // Pretty-print JSON
	err = encoder.Encode(userCredentials)
	if err != nil {
		file.Close() // Close before removing
		os.Remove(tempFile)
		return fmt.Errorf("could not encode users data to %s: %w", tempFile, err)
	}

	// Explicitly close the file before renaming to ensure data is flushed
	if err := file.Close(); err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("could not close temporary users file %s: %w", tempFile, err)
	}

	// Rename the temporary file to the actual file (atomic on most OS)
	if err := os.Rename(tempFile, usersFile); err != nil {
		removeErr := os.Remove(tempFile)
		if removeErr != nil {
			log.Printf("Warning: Failed to remove temporary file %s after rename failed: %v", tempFile, removeErr)
		}
		return fmt.Errorf("could not rename temporary users file %s to %s: %w", tempFile, usersFile, err)
	}
	log.Printf("Successfully saved %d SOCKS users to %s", len(userCredentials), usersFile)
	return nil
}

// addOrUpdateUser добавляет или обновляет пользователя в базе данных
func addOrUpdateUser(username string, password string, interval time.Duration) error {
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}
	hashedPassword, err := hashPassword(password)
	if err != nil {
		return err // Error already formatted in hashPassword
	}

	mu.Lock() // Lock for writing to userCredentials and file
	defer mu.Unlock()

	// Use default interval if provided interval is zero or negative
	if interval <= 0 {
		interval = defaultRotationInterval
	}

	userCredentials[username] = userConfig{Password: hashedPassword, RotationInterval: interval}
	log.Printf("User '%s' added or updated (rotation interval %s).", username, interval) // Log before saving

	// Save changes to file
	if err := saveUsersToFileLocked(); err != nil {
		log.Printf("CRITICAL: Failed to save users file after updating user '%s': %v", username, err)
		return fmt.Errorf("failed to save user data to file: %w", err)
	}
	return nil
}

// deleteUser удаляет пользователя из базы данных
func deleteUser(username string) error {
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}
	if username == adminUsername {
		return fmt.Errorf("cannot delete the admin user ('%s')", adminUsername) // Prevent admin deletion
	}

	mu.Lock() // Lock for writing to userCredentials and file
	defer mu.Unlock()

	if _, ok := userCredentials[username]; ok {
		delete(userCredentials, username)
		log.Printf("User '%s' deleted.", username) // Log before saving

		// Save changes to file
		if err := saveUsersToFileLocked(); err != nil {
			log.Printf("CRITICAL: Failed to save users file after deleting user '%s': %v", username, err)
			return fmt.Errorf("failed to save user data to file after deleting user: %w", err)
		}
		return nil
	}
	return fmt.Errorf("user '%s' not found", username)
}

// createneadedfiles creates essential config files if they don't exist.
func createneadedfiles() error {
	files := []string{proxyFile, whitelistFile, usersFile}
	for _, filename := range files {
		if _, err := os.Stat(filename); os.IsNotExist(err) {
			log.Printf("File '%s' not found, creating empty file.", filename)
			file, err := os.Create(filename)
			if err != nil {
				return fmt.Errorf("could not create %s: %w", filename, err)
			}
			// Write empty JSON object to users file if creating it
			if filename == usersFile {
				if _, err := file.WriteString("{}"); err != nil {
					file.Close() // Close before returning error
					return fmt.Errorf("could not write initial empty object to %s: %w", filename, err)
				}
			}
			if err := file.Close(); err != nil {
				// Log error but continue, as file creation itself succeeded
				log.Printf("Warning: could not close newly created file %s: %v", filename, err)
			}
			log.Printf("Created empty file %s", filename)
		} else if err != nil {
			// Other error trying to stat the file
			return fmt.Errorf("could not check status of file %s: %w", filename, err)
		}
	}
	return nil
}

// readWhitelistFromFile reads the whitelist from its file.
func readWhitelistFromFile() ([]string, error) {
	file, err := os.Open(whitelistFile)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Whitelist file '%s' not found, starting with empty whitelist.", whitelistFile)
			return []string{}, nil
		}
		return nil, fmt.Errorf("error opening whitelist file %s: %w", whitelistFile, err)
	}
	defer file.Close()
	var loadedWhitelist []string
	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.Contains(line, "/") {
			if _, _, err := net.ParseCIDR(line); err != nil {
				log.Printf("Warning: Invalid CIDR format '%s' in %s at line %d, skipping.", line, whitelistFile, lineNum)
				continue
			}
		} else {
			if net.ParseIP(line) == nil {
				log.Printf("Warning: Invalid IP address format '%s' in %s at line %d, skipping.", line, whitelistFile, lineNum)
				continue
			}
		}
		loadedWhitelist = append(loadedWhitelist, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning whitelist file %s: %w", whitelistFile, err)
	}
	log.Printf("Loaded %d entries from client whitelist file %s", len(loadedWhitelist), whitelistFile)
	return loadedWhitelist, nil
}

// writeWhitelistToFileLocked writes the whitelist to file. Assumes lock is held.
func writeWhitelistToFileLocked(currentWhitelist []string) error {
	tempFile := whitelistFile + ".tmp"
	file, err := os.Create(tempFile)
	if err != nil {
		return fmt.Errorf("could not create temporary whitelist file %s: %w", tempFile, err)
	}
	// No defer, explicitly close before rename
	writer := bufio.NewWriter(file)
	for _, ip := range currentWhitelist {
		if _, err := writer.WriteString(ip + "\n"); err != nil {
			file.Close()
			os.Remove(tempFile)
			return fmt.Errorf("could not write to temporary whitelist file %s: %w", tempFile, err)
		}
	}
	if err := writer.Flush(); err != nil {
		file.Close()
		os.Remove(tempFile)
		return fmt.Errorf("could not flush whitelist writer for %s: %w", tempFile, err)
	}
	if err := file.Close(); err != nil {
		os.Remove(tempFile)
		return fmt.Errorf("could not close temporary whitelist file %s: %w", tempFile, err)
	}
	if err := os.Rename(tempFile, whitelistFile); err != nil {
		removeErr := os.Remove(tempFile)
		if removeErr != nil {
			log.Printf("Warning: Failed to remove temporary file %s after rename failed: %v", tempFile, removeErr)
		}
		return fmt.Errorf("could not rename temporary whitelist file %s to %s: %w", tempFile, whitelistFile, err)
	}
	log.Printf("Successfully saved %d entries to %s", len(currentWhitelist), whitelistFile)
	return nil
}


// --- Admin Web UI / API Logic (REMOVED) ---

// --- Main Function ---

func main() {
	// Define default values
	serverPort = defaultServerPort // This is now the SOCKS5 server port
	// apiPort = defaultAPIPort // Removed
	listenAddress = defaultListenAddress
	rotationInterval = defaultRotationInterval

	// --- Argument Parsing ---
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		arg := args[i]
		var value string
		if strings.Contains(arg, "=") {
			parts := strings.SplitN(arg, "=", 2)
			arg = parts[0]
			value = parts[1]
		} else if i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
			value = args[i+1]
			i++
		} else {
            value = ""
        }

		switch arg {
		case "--serverPort", "-sp": // Port for the SOCKS5 server
			p, err := strconv.Atoi(value)
			if err != nil || value == "" {
				log.Fatalf("Invalid value for SOCKS5 server port: '%s' (%v)", value, err)
			}
			serverPort = p
		// case "--apiPort", "-ap": // Removed API Port flag
		// 	p, err := strconv.Atoi(value)
		// 	if err != nil || value == "" {
		// 		log.Fatalf("Invalid value for Admin/API port: '%s' (%v)", value, err)
		// 	}
		// 	apiPort = p
		case "--listenAddress", "-la":
			if value == "" {
				log.Fatalf("Missing value for listen address flag (--listenAddress or -la)")
			}
			if value != "" && net.ParseIP(value) == nil {
                 log.Printf("Warning: Listen address '%s' is not a standard IP format, attempting to use anyway.", value)
			}
			listenAddress = value
		case "--rotationInterval", "-ri": // Interval for checking upstream proxies
             if value == "" {
                log.Fatalf("Missing value for rotation interval flag (--rotationInterval or -ri)")
            }
			duration, err := time.ParseDuration(value)
			if err != nil {
				log.Fatalf("Invalid rotation interval duration: '%s' (%v)", value, err)
			}
            if duration <= 0 {
                log.Fatalf("Rotation interval must be a positive duration: '%s'", value)
            }
			rotationInterval = duration
		case "--adminUser", "-au": // Still needed for deleteUser check
			if value == "" {
				log.Fatalf("Missing value for admin username flag (--adminUser or -au)")
			}
			adminUsername = value
		case "--help", "-h":
			fmt.Println("Usage: go-proxy [options]")
			fmt.Println("Options:")
			fmt.Println("  --serverPort=<port>, -sp <port>       Port for the SOCKS5 server (default: 8080)")
			// fmt.Println("  --apiPort=<port>, -ap <port>          Port for the admin/API web interface (default: 8082)") // Removed
			fmt.Println("  --listenAddress=<ip>, -la <ip>      IP address to listen on (default: 0.0.0.0)")
			fmt.Println("  --rotationInterval=<dur>, -ri <dur> Interval for checking upstream proxies (default: 5m)")
			fmt.Println("  --adminUser=<user>, -au <user>      Username designated as admin (prevents deletion) (default: admin)") // Clarified help
			fmt.Println("  --help, -h                          Show this help message")
			fmt.Println("\nRequired files (created if missing):")
			fmt.Printf("  - %s (Upstream proxy list, format: ip:port or user:pass@ip:port)\n", proxyFile)
			fmt.Printf("  - %s (SOCKS5 user credentials, JSON format)\n", usersFile)
			fmt.Printf("  - %s (Client IP/CIDR whitelist, one per line)\n", whitelistFile)
			// fmt.Println("\nRequired directories (created if missing):") // No longer needed
			// fmt.Println("  - static/ (Contains index.html, CSS, JS files for Admin Web UI)") // Removed
			os.Exit(0)
		default:
            if strings.HasPrefix(arg, "-") {
                 log.Printf("Warning: Unknown or potentially incomplete flag: %s", arg)
            } else {
                 log.Printf("Warning: Ignoring unexpected argument: %s", arg)
            }
		}
	}

	log.Printf("--- Configuration ---")
	log.Printf("SOCKS5 Server Port:     %d", serverPort)
	// log.Printf("Admin/API Port:         %d", apiPort) // Removed
	log.Printf("Listen Address:         %s", listenAddress)
	log.Printf("Upstream Rotation Intrv:%s", rotationInterval)
	log.Printf("Admin Username:         %s", adminUsername)
	log.Printf("Upstream Proxy File:    %s", proxyFile)
	log.Printf("SOCKS Users File:       %s", usersFile)
	log.Printf("Client Whitelist File:  %s", whitelistFile)
	log.Printf("---------------------")

	// --- Initialization ---
	rand.Seed(time.Now().UnixNano())

	// Use the restored function
	if err := createneadedfiles(); err != nil {
		log.Fatalf("Error creating necessary files: %v", err)
	}
    // staticDir := "static" // No longer needed
    // if _, err := os.Stat(staticDir); os.IsNotExist(err) { ... } // No longer needed


	// Use the restored function
	loadedUsers, err := loadUsersFromFile()
	if err != nil {
		log.Fatalf("Error loading SOCKS users from file '%s': %v", usersFile, err)
	}
	userCredentials = loadedUsers

	// Check if admin user exists in the user file (needed for deleteUser check)
	// No need to prompt for password here if web UI is gone
	mu.RLock()
	_, adminExists := userCredentials[adminUsername]
	mu.RUnlock()
	if !adminExists {
		log.Printf("Warning: Designated admin user '%s' not found in %s. Deletion protection for this user will not apply.", adminUsername, usersFile)
	} else {
		log.Printf("Admin user '%s' loaded (used for deletion check).", adminUsername)
	}

	// Load upstream proxies
	initialProxies, err := loadProxies(proxyFile)
	if err != nil {
		log.Printf("Warning: Error loading upstream proxies from '%s': %v.", proxyFile, err)
		allProxies = []proxyEntry{}
	} else {
		allProxies = initialProxies
	}
	log.Println("Performing initial check of upstream proxies...")
	initialWorkingProxies := getWorkingProxies(allProxies)
	mu.Lock()
	workingProxies = initialWorkingProxies
	mu.Unlock()
	log.Printf("Initial check complete: Found %d working upstream proxies out of %d.", len(initialWorkingProxies), len(allProxies))


	// Load client IP whitelist
	loadedWhitelist, err := readWhitelistFromFile()
	if err != nil {
		log.Printf("Warning: Error reading client whitelist from file '%s': %v. Starting with empty whitelist.", whitelistFile, err)
		whitelist = []string{}
	} else {
		mu.Lock()
		whitelist = loadedWhitelist
		mu.Unlock()
	}

	// Initialize Go templates (REMOVED)
	// if err := initTemplates(); err != nil { ... }


	// --- Goroutine for Periodic Upstream Proxy Update ---
	go func() {
		if rotationInterval <= 0 {
			log.Println("Upstream proxy rotation disabled (interval is zero or negative).")
			return
		}
		log.Printf("Starting periodic upstream proxy update routine (interval: %s)...", rotationInterval)
		ticker := time.NewTicker(rotationInterval)
		defer ticker.Stop()
		for range ticker.C {
			log.Printf("Background task: Updating list of working upstream proxies...")
			newProxies, err := loadProxies(proxyFile)
			if err != nil {
				log.Printf("Error loading upstream proxies during update: %v", err)
				continue
			}
			newWorkingProxies := getWorkingProxies(newProxies)
			mu.Lock()
			allProxies = newProxies
			workingProxies = newWorkingProxies // Update the list used by SOCKS5 handler
			currentWorkingCount := len(workingProxies)
			currentTotalCount := len(allProxies)
			mu.Unlock()
			log.Printf("Background task: Upstream proxy update complete. Found %d working proxies out of %d.", currentWorkingCount, currentTotalCount)
		}
	}()


	// --- Setup Admin/API HTTP Server (REMOVED) ---
	// apiMux := http.NewServeMux() ...
	// go func() { ... }()


	// --- Setup SOCKS5 Server ---
	socksListener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", listenAddress, serverPort))
	if err != nil {
		log.Fatalf("Error starting SOCKS5 server listener on %s:%d: %v", listenAddress, serverPort, err)
	}
	defer socksListener.Close()

	log.Printf("SOCKS5 server listening on %s:%d", listenAddress, serverPort)
	log.Println("Waiting for incoming SOCKS5 connections...")

	// --- Accept Loop for SOCKS5 Server ---
	for {
		clientConn, err := socksListener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed network connection") {
				log.Println("SOCKS5 server listener closed, exiting accept loop.")
				break
			}
			log.Printf("Error accepting SOCKS5 connection: %v", err)
			continue
		}
		// Handle SOCKS5 connection in a new goroutine
		go handleSocksConnection(clientConn)
	}

	log.Println("Main function exiting.")
	// TODO: Implement graceful shutdown for SOCKS5 server listener
}
