// Package admin contains admin panel handlers.
package admin

import (
	"callgraph_target/db"
	"net/http"
)

// AdminHandler is an HTTP handler for the admin panel.
func AdminHandler(w http.ResponseWriter, r *http.Request) {
	action := r.FormValue("action")

	if action == "export" {
		// Cross-file call: admin → db
		data, _ := db.ReadFile("/var/log/" + r.FormValue("logfile"))
		w.Write(data)
		return
	}

	w.Write([]byte("Admin panel"))
}

// Helper is a safe function — same name as db.Helper but different package.
// This is a FALSE POSITIVE test: call graph may confuse admin.Helper with db.Helper.
func Helper() string {
	return "admin helper"
}
