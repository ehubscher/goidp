package main

import (
	"fmt"
	"net/http"
)

type Route struct {
	Method  string
	Path    string
	Handler http.Handler
}

type Router struct {
	Mux         *http.ServeMux
	Routes      map[string]Route
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
// TODO: Check that the given route.Method is indeed a valid HTTP verb.
func (r *Router) RegisterHandlers() {
	for _, route := range r.Routes {
		r.Mux.Handle(fmt.Sprintf("%s %s", route.Method, route.Path), route.Handler)
	}
}
