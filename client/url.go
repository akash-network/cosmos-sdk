package client

import (
	"net/url"
	"strings"
)

const (
	protoHTTP  = "http"
	protoHTTPS = "https"
	protoWSS   = "wss"
	protoWS    = "ws"
	protoTCP   = "tcp"
	protoUNIX  = "unix"
)

//-------------------------------------------------------------

// Parsed URL structure
type parsedURL struct {
	url.URL

	isUnixSocket bool
}

// Parse URL and set defaults
func newParsedURL(remoteAddr string) (*parsedURL, error) {
	u, err := url.Parse(remoteAddr)
	if err != nil {
		return nil, err
	}

	// default to tcp if nothing specified
	if u.Scheme == "" {
		u.Scheme = protoTCP
	}

	pu := &parsedURL{
		URL:          *u,
		isUnixSocket: false,
	}

	if u.Scheme == protoUNIX {
		pu.isUnixSocket = true
	}

	return pu, nil
}

// Change protocol to HTTP for unknown protocols and TCP protocol - useful for RPC connections
func (u *parsedURL) SetDefaultSchemeHTTP() {
	// protocol to use for http operations, to support both http and https
	switch u.Scheme {
	case protoHTTP, protoHTTPS, protoWS, protoWSS:
		// known protocols not changed
	default:
		// default to http for unknown protocols (ex. tcp)
		u.Scheme = protoHTTP
	}
}

// Get full address without the protocol - useful for Dialer connections
func (u parsedURL) GetHostWithPath() string {
	// Remove protocol, userinfo and # fragment, assume opaque is empty
	return u.Host + u.EscapedPath()
}

// Get a trimmed address - useful for WS connections
func (u parsedURL) GetTrimmedHostWithPath() string {
	// if it's not an unix socket we return the normal URL
	if !u.isUnixSocket {
		return u.GetHostWithPath()
	}
	// if it's a unix socket we replace the host slashes with a period
	// this is because otherwise the http.Client would think that the
	// domain is invalid.
	return strings.ReplaceAll(u.GetHostWithPath(), "/", ".")
}

// GetDialAddress returns the endpoint to dial for the parsed URL
func (u parsedURL) GetDialAddress() string {
	// if it's not a unix socket we return the host, example: localhost:443
	if !u.isUnixSocket {
		return u.Host
	}
	// otherwise we return the path of the unix socket, ex /tmp/socket
	return u.GetHostWithPath()
}

// Get a trimmed address with protocol - useful as address in RPC connections
func (u parsedURL) GetTrimmedURL() string {
	return u.Scheme + "://" + u.GetTrimmedHostWithPath()
}
