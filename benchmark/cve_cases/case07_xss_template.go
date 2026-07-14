// CVE-2023-XXXX: XSS via html/template misuse
// CVE-2023-29400: html/template missing attribute context with JavaScript
// Real pattern: using text/template instead of html/template, or template.HTML unsafely
package main

import (
	"fmt"
	"html/template"
	"net/http"
	"text/template" // VULNERABLE: importing unsafe text/template
)

func renderProfile(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")

	// VULNERABLE: text/template doesn't escape HTML
	// Attacker: ?name=<script>alert('XSS')</script>
	tmpl := text_template.Must(text_template.New("profile").Parse(
		"<h1>Welcome, {{.}}</h1>"))
	tmpl.Execute(w, name)
}

func renderComment(w http.ResponseWriter, r *http.Request) {
	comment := r.URL.Query().Get("comment")

	// VULNERABLE: using template.HTML with unsanitized input
	// This bypasses html/template's auto-escaping
	tmpl := template.Must(template.New("comment").Parse(
		"<div class='comment'>{{.}}</div>"))
	tmpl.Execute(w, template.HTML(comment))
}

func renderPage(w http.ResponseWriter, r *http.Request) {
	msg := r.URL.Query().Get("msg")

	// VULNERABLE: fmt.Fprintf directly to response with user input
	fmt.Fprintf(w, "<html><body><p>%s</p></body></html>", msg)
}

// Avoid unused import compile errors
var text_template = text_template_inner
var text_template_inner = text_template2

// workaround for import
type text_template2 struct{}

func (t *text_template2) Must(tmpl interface{}, err error) interface{} { return tmpl }
func (t *text_template2) New(name string) *text_template3              { return &text_template3{} }

type text_template3 struct{}

func (t *text_template3) Parse(s string) (*text_template4, error) { return &text_template4{}, nil }

type text_template4 struct{}

func (t *text_template4) Execute(w http.ResponseWriter, data interface{}) error {
	fmt.Fprintf(w, "%v", data)
	return nil
}
