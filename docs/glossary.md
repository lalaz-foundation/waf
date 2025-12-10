# Glossary

Terminology and definitions for the WAF package.

---

## A

### APCu
Alternative PHP Cache (user). A caching system for PHP that stores data in shared memory. Used as a rate limit storage backend for single-server deployments.

## C

### CIDR
Classless Inter-Domain Routing. A method for allocating IP addresses and routing. Example: `192.168.1.0/24` represents addresses from `192.168.1.0` to `192.168.1.255`.

### Command Injection
A security vulnerability where an attacker can execute arbitrary shell commands on the server by injecting malicious input into a command string.

### CORS
Cross-Origin Resource Sharing. A browser security feature that controls how resources can be requested from different origins (domains).

### CSP
Content Security Policy. An HTTP header that helps prevent XSS attacks by specifying which resources the browser should load.

## D

### DoS
Denial of Service. An attack that makes a service unavailable by overwhelming it with requests.

### DDoS
Distributed Denial of Service. A DoS attack from multiple sources simultaneously.

## G

### GeoIP
Technology that maps IP addresses to geographic locations (country, city, etc.).

### GeoLocation
A value object representing geographic information about an IP address, including country, region, city, and coordinates.

## H

### Helmet
A middleware that sets various HTTP security headers to protect against common vulnerabilities.

### HSTS
HTTP Strict Transport Security. A header that forces browsers to use HTTPS for all connections.

## I

### IP Blacklist
A list of IP addresses that are blocked from accessing the application.

### IP Whitelist
A list of IP addresses that are allowed to access the application (all others are blocked).

### ISO 3166-1 alpha-2
A two-letter country code standard (e.g., US, CA, BR, GB).

## L

### Loopback Address
An IP address that refers to the local machine. `127.0.0.1` for IPv4, `::1` for IPv6.

## M

### MaxMind
A company providing GeoIP databases for mapping IP addresses to locations.

### Middleware
A component that intercepts and processes HTTP requests/responses in a pipeline.

## O

### Origin
In CORS context, the combination of protocol, host, and port that identifies where a request comes from.

## P

### Path Traversal
A security vulnerability where an attacker accesses files outside the intended directory by using `../` sequences.

### Pattern Set
A collection of regular expressions used to detect specific types of threats.

### Preflight Request
An OPTIONS request sent by browsers before certain cross-origin requests to check if the actual request is allowed.

### Private IP
An IP address reserved for internal networks, not routable on the public internet. Ranges include `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`.

### Proxy
An intermediary server that forwards requests between clients and servers. Can be a forward proxy (client-side) or reverse proxy (server-side).

## R

### Rate Limiting
Controlling the number of requests a client can make within a time window.

### Retry-After
An HTTP header indicating how long a client should wait before making another request after being rate limited.

## S

### SQL Injection
A security vulnerability where an attacker executes malicious SQL queries by injecting code into input fields.

### Sanitization
The process of cleaning or filtering input data to remove or escape potentially harmful content.

### Severity
A numeric rating (1-10) indicating the potential impact of a security threat.

## T

### Threat
A detected security issue in the input data, including the type, matched pattern, and matched value.

### Threat Detection
The process of scanning input data for known attack patterns.

### ThreatType
An enumeration of detectable attack types: XSS, SQL_INJECTION, PATH_TRAVERSAL, COMMAND_INJECTION.

### Token Bucket
A rate limiting algorithm that allows bursts of traffic while maintaining an average rate limit.

### Tor
The Onion Router. An anonymity network that routes traffic through multiple relays.

### Trusted Proxy
A reverse proxy that is trusted to provide accurate client IP addresses via headers like `X-Forwarded-For`.

## V

### VPN
Virtual Private Network. A technology that creates an encrypted connection over the internet.

## W

### WAF
Web Application Firewall. A security system that monitors and filters HTTP traffic to protect web applications.

### Wildcard
A pattern character (`*`) that matches any sequence of characters in IP addresses.

## X

### X-Forwarded-For
An HTTP header containing the client's original IP address when behind a proxy.

### X-Frame-Options
An HTTP header that controls whether a page can be displayed in a frame.

### X-XSS-Protection
An HTTP header that enables the browser's built-in XSS filter.

### XSS
Cross-Site Scripting. A security vulnerability where an attacker injects malicious scripts into web pages.
