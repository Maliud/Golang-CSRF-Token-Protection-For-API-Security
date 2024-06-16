package db

import (
	"errors"
	"log"
	"github.com/Maliud/Golang-CSRF-Token-Protection-For-API-Security/db/models"
	"github.com/Maliud/Golang-CSRF-Token-Protection-For-API-Security/randomstrings"
	"golang.org/x/crypto/bcrypt"
)


var users = map[string]models.User{}
var refreshTokens map[string]string

func StoreUser(username string, password string, role string)(uuid string, err error) {
	uuid, err =  randomstrings.GenerateRadomString(32)
	if err != nil {
		return "", err
	}

	u := models.User{};
	for u != users[uuid]{
		uuid, err = randomstrings.GenerateRadomString(32)
		if err != nil{
			return "", err
		}
	}
	PasswordHash, hashErr := generateBcrypHash(password)
	if hashErr != nil {
		err = hashErr
		return
	}
	users[uuid] = models.User{username, PasswordHash, role}
	return uuid, err
}

func InitDB() {
	refreshTokens = make(map[string]string)
}

func DeleteUser(uuid string)(models.User, error) {
	delete(users, uuid)
	
	
}

func FetchUserById(uuid string)(models.User, error){
	u := users[uuid]
	blankUser := models.User{}

	if blankUser != u {
		return u, nil
	}else {
		return u, errors.New("Verilen uuid ile eşleşen kullanıcı bulunamadı")
	}
}

func FetchUserByUsername(username string)(models.User, string, error){
	for k, v := range users{
		if v.Username == username{
			return v,k, nil
		}
	}

	return models.User{}, "", errors.New("Verilen kullanıcı adıyla eşleşen kullanıcı bulunamadı")
}

func StoreRefreshToken()(jti string, err error){
	jti, err = randomstrings.GenerateRadomString(32)
	if err != nil {
		return jti, err
	}
	for refreshTokens[jti] != "" {
		jti, err = randomstrings.GenerateRadomString(32)
		if err != nil{
			return jti, err
		}
	}

	refreshTokens[jti] = "valid"
	return jti, err
}

func DeleteRefreshToken(jti string){
	delete(refreshTokens, jti)
}

func CheckRefreshToken(jti string) bool {
	return refreshTokens[jti] != ""
}

func LogUserIn(username string, password string)(models.User, string, error){
	user, uuid, userErr := FetchUserByUsername(username)
	log.Println(user, uuid, userErr)
	if userErr != nil {
		return models.User{}, "", userErr
	}

	return user, uuid, checkPasswordAgainHash(user.PasswordHash, password)
}

func generateBcrypHash(password string)(string, error){
	hash, err :=  bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash[:]), err
}

func checkPasswordAgainHash(hash string, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}