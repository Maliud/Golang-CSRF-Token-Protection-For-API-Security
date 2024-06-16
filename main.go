package main

import (
	"log"

	"github.com/Maliud/Golang-CSRF-Token-Protection-For-API-Security/db"
	"github.com/Maliud/Golang-CSRF-Token-Protection-For-API-Security/server"
	myjwt "github.com/Maliud/Golang-CSRF-Token-Protection-For-API-Security/server/middleware/myJwt"
)


var host = "localhost"
var port = "9000"
func main() {
	db.InitDB()

	jwtErr := myjwt.InitJWT()
	if jwtErr != nil {
		log.Println("JWT başlatılırken hata oluştu!")
		log.Fatal(jwtErr)
	}

	serverErr := server.StartServer(host, port)
	if serverErr != nil {
		log.Println("Sunucu başlatılırken hata oluştu!")
		log.Fatal(serverErr)
	}
}