package main

import (
	"callgraph_target/admin"
	"callgraph_target/handlers"
	"log"
	"net/http"
)

func main() {
	// Register HTTP handlers — these are the entry points
	http.HandleFunc("/login", handlers.LoginHandler)
	http.HandleFunc("/file", handlers.FileHandler)
	http.HandleFunc("/health", handlers.HealthHandler)
	http.HandleFunc("/admin", admin.AdminHandler)

	log.Println("Server starting on :8080")
	http.ListenAndServe(":8080", nil)
}
