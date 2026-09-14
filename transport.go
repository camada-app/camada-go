package camada

import "github.com/camada-app/camada-go/internal/transport"

// HTTPRequest is one call to the analyst, as the Transport seam sees it.
type HTTPRequest = transport.Request

// HTTPResponse is the analyst's answer; Status 0 means the request never got one.
type HTTPResponse = transport.Response

// Transport performs one HTTPRequest. The engine, the snapshot client and the event queue all
// go through it, so tests inject an in-process fake and production uses HTTPTransport.
type Transport = transport.Transport

// HTTPTransport is the production transport over net/http: 2-3 s deadlines, transparent gzip,
// never panics (a network failure is a status-0 response).
func HTTPTransport(req HTTPRequest) HTTPResponse { return transport.HTTP(req) }
