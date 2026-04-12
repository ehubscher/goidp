package routing

import (
	"fmt"
	"net/http"
	"strings"
)

type HttpMethod int

const (
	GET HttpMethod = iota
	POST
	PUT
	DELETE
	PATCH
	OPTIONS
	HEAD
)

var httpMethods = map[string]HttpMethod{
	http.MethodGet:     GET,
	http.MethodPost:    POST,
	http.MethodPut:     PUT,
	http.MethodDelete:  DELETE,
	http.MethodPatch:   PATCH,
	http.MethodOptions: OPTIONS,
	http.MethodHead:    HEAD,
}

func IsValidHttpMethod(s string) bool {
	if s == "" {
		return false
	}

	_, ok := httpMethods[strings.ToUpper(strings.TrimSpace(s))]
	return ok
}

type Middleware func(http.Handler) http.Handler

type Route struct {
	Method  string
	Path    string
	Handler http.Handler
}

type Router struct {
	Mux         *http.ServeMux
	Routes      []Route
	Middlewares []Middleware
}

// Configure all registered Middleware to each route.
func (r *Router) WrapMiddlewares() {
	var h http.Handler

	for _, route := range r.Routes {
		// Chain all of the Middleware functions by wrapping themselves over each other, starting with the route.Handler.
		// This will execute all of the Middleware functions in subsequent order before executing any given handler.
		h = route.Handler
		for _, m := range r.Middlewares {
			h = m(h)
		}

		// Each handler now has every single registered Middleware wrapped around it successively.
		route.Handler = h
	}
}

// Register each route handler to the router's Mux.
func (r *Router) RegisterHandlers() {
	for _, route := range r.Routes {
		if !IsValidHttpMethod(route.Method) {
			// TODO: Fatal...?
			continue
		}

		r.Mux.Handle(fmt.Sprintf("%s %s", route.Method, route.Path), route.Handler)
	}
}
