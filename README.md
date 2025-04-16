# Go SOCKS5 Proxy Server with Rotation and Authentication

This is a simple SOCKS5 proxy server written in Go. It accepts incoming SOCKS5 connections, authenticates clients (either by IP from a whitelist or by username/password), and forwards traffic through one of the randomly selected outgoing (upstream) proxies from a provided list. The server also periodically checks the availability of the upstream proxies.

## Key Features

* **SOCKS5 Server:** Implements the SOCKS5 protocol (RFC 1928).
* **Authentication:**
    * **IP Whitelist:** Clients whose IP addresses are listed in `whitelist.txt` can connect without authentication (using the SOCKS5 "No Authentication Required" method, 0x00).
    * **Username/Password:** Clients not on the whitelist must use the SOCKS5 "Username/Password Authentication" method (RFC 1929) with credentials from the `users.json` file. Passwords are stored as bcrypt hashes.
* **Upstream Proxy Rotation:** Traffic is forwarded through a randomly selected working proxy from the `socks5_proxies.txt` list.
* **Upstream Proxy Health Check:** The server periodically checks the availability of proxies from the list and only uses working ones.
* **Connection Retries:** If establishing a connection with the selected upstream proxy fails during the client's initial request, the server automatically attempts to connect via several other working proxies (up to 3 attempts).
* **File-Based Configuration:** User management, whitelist, and the upstream proxy list are managed through text/JSON files.
* **Argument-Based Settings:** The SOCKS5 server port, listening address, and proxy check interval can be configured via command-line arguments.

## Requirements

* Go Compiler (version 1.18 or higher recommended).

## Configuration Files

The script will create the necessary files on the first run if they are missing.

1.  **`socks5_proxies.txt`**: List of outgoing (upstream) proxy servers.
    * Format: One proxy per line.
    * `IP:PORT` (for proxies without authentication)
    * `USERNAME:PASSWORD@IP:PORT` (for proxies with authentication)
    * Lines starting with `#` are ignored.
    * Example:
        ```
        # Comment
        1.1.1.1:1080
        user1:pass1@2.2.2.2:1080
        3.3.3.3:8000
        ```

2.  **`users.json`**: User credentials for SOCKS5 authentication.
    * Format: JSON object where the key is the username, and the value is an object containing the password hash (`Password`) and rotation interval (`RotationInterval` - currently unused by the server but saved).
    * **Important:** Do not edit the `Password` field manually. Passwords are hashed automatically when added/changed via the (removed) web interface or on the first run for the `admin` user. If adding users manually, leave the `Password` field empty or remove it; the script will prompt for a password on the first run for the `admin` user if it's not set.
    * Example (after hashing):
        ```json
        {
          "admin": {
            "Password": "$2a$10$abcdefghijklmnopqrstuv",
            "RotationInterval": 300000000000
          },
          "user1": {
            "Password": "$2a$10$wxyzabcdefghijklmnop",
            "RotationInterval": 300000000000
          }
        }
        ```

3.  **`whitelist.txt`**: Whitelist of client IP addresses or CIDR subnets allowed to connect without password authentication.
    * Format: One IP address or CIDR per line.
    * Lines starting with `#` are ignored.
    * Example:
        ```
        # Local machine
        127.0.0.1
        # Trusted subnet
        192.168.1.0/24
        # Specific IP
        8.8.8.8
        ```

## Build

To build the executable, run:

```bash
go build proxy.go
UsageRun the compiled binary. You can specify parameters via command-line arguments:./proxy [arguments]
Command-Line Arguments:--serverPort=<port> or -sp <port>: Port for the SOCKS5 server (default: 8080).--listenAddress=<ip> or -la <ip>: IP address for the server to listen on (default: 0.0.0.0 - all interfaces).--rotationInterval=<dur> or -ri <dur>: Interval for checking upstream proxies (e.g., 5m, 1h, 30s) (default: 5m).--adminUser=<user> or -au <user>: Username designated as administrative (prevents accidental deletion of this user if management features were present) (default: admin).--help or -h: Show help message for arguments.Example:./proxy --serverPort=1080 --listenAddress=192.168.1.100 --rotationInterval=10m
Client ConnectionClients should connect to the address and port specified by --listenAddress and --serverPort.If the client's IP address is in whitelist.txt, the client should configure their SOCKS5 client to use the "No Authentication Required" method.If the client's IP address is not in whitelist.txt, the client must configure their
