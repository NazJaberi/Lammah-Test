package main

import (
	lammah "lammah/internal"

	"log"
	"net/http"

	"github.com/gorilla/mux"
)

func main() {
    r := mux.NewRouter()

    // Auth routes
    r.HandleFunc("/register", lammah.RegisterHandler).Methods("POST")
    r.HandleFunc("/login", lammah.LoginHandler).Methods("POST")
    r.HandleFunc("/logout", lammah.LogoutHandler).Methods("POST")


    // Apply auth middleware to protected routes
    r.Use(lammah.AuthMiddleware)

    log.Fatal(http.ListenAndServe(":8080", r))
}