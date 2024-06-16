package models

import (
	"time"

	"github.com/Maliud/Golang-CSRF-Token-Protection-For-API-Security/randomstrings"
	jwt "github.com/dgrijalva/jwt-go"
)


type User struct {
	Username, PasswordHash, Role string
	
}

type TokenClaims struct {
	jwt.StandardClaims
	Role string `json:"role"`
	Csrf string `json:"csrf"`
}

const RefreshTokenValidTime = time.Hour * 72
const AuthTokenValidTime = time.Minute * 15

func GenerateCSRFSecret() (string, error) {
	return randomstrings.GenerateCSRFSecret(32)
}