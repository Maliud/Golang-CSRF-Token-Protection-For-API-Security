package server

import (
	"log"
	"net/http"

	"github.com/Maliud/Golang-CSRF-Token-Protection-For-API-Security/server/middleware"
)


func StartServer(hostname string, port string) error {
	host := hostname + ":" + port
	log.Printf("PORT DİNLENİYOR: %s", host )

	handler := middleware.NewHandler()

	http.Handle("/", handler)
	return http.ListenAndServe(host, nil)
}