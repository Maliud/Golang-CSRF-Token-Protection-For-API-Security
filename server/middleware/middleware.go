package middleware

import (
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/Maliud/Golang-CSRF-Token-Protection-For-API-Security/db"
	myjwt "github.com/Maliud/Golang-CSRF-Token-Protection-For-API-Security/server/middleware/myJwt"
	"github.com/Maliud/Golang-CSRF-Token-Protection-For-API-Security/server/templates"
	"github.com/justinas/alice"
)

func NewHandler() http.Handler {
	return alice.New(recoverHandler, authHandler).ThenFunc(logicHandler)
}

func recoverHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Panic("Kurtarıldı!:%+v", err)
				http.Error(w, http.StatusText(500), 500)
			}
		}()
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func authHandler(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/restricted", "/logout", "/deleteUser":
			log.Println("Auth Restricted kısmında")
			AuthCookie, authErr := r.Cookie("AuthToken")
			if authErr == http.ErrNoCookie{
				log.Println("Yetkisiz girişim! auth çerezi yok")
				nullifyTokenCookies(&w, r)
				http.Error(w, http.StatusText(401), 401)
				return
			} else if authErr != nil {
				log.Panic("Panic: %+v", authErr)
				nullifyTokenCookies(&w, r)
				http.Error(w, http.StatusText(500), 500)
				return
			}

			RefreshCookie, refreshErr := r.Cookie("RefreshToken")
			if refreshErr == http.ErrNoCookie{
				log.Println("İzinsiz deneme! çerez yenileme yok")
				nullifyTokenCookies(&w, r)
				http.Redirect(w, r, "/login", 302)
				return
			} else if refreshErr != nil {
				log.Panic("Panic: %+v", refreshErr)
				nullifyTokenCookies(&w, r)
				http.Error(w, http.StatusText(500), 500)
				return
			}
			requestCsrfToken :=  grabCsrfFromReq(r)
			log.Println(requestCsrfToken)

			authTokenString, refreshTokenString, csrfSecret, err :=  myjwt.CheckAndRefreshTokens(AuthCookie.Value, RefreshCookie.Value, requestCsrfToken)
			if err != nil {
				if err.Error() == "Unauthorized" {
					log.Println("Yetkisiz girişim! JWT geçerli değil!")
					http.Error(w, http.StatusText(401), 401)
					return
				}else {
					log.Panic("err not nill")
					log.Panic("panic: %+v", err)
					http.Error(w, http.StatusText(500), 500)
					return
				}
			}
			log.Println("jwts başarıyla yeniden oluşturuldu")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
			w.Header().Set("X-CSRF-TOKEN", csrfSecret)

		default:
			// no check necessary gerekliligi yok
		}
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func logicHandler(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/restricted":
		csrfSecret := grabCsrfFromReq(r)
		templates.RenderTemplate(w, "resricted", &templates.RestrictedPage{csrfSecret, "Merhaba Muhammed Ali Ud"})
	case "/login":
		switch r.Method {
		case "GET":
			templates.RenderTemplate(w, "login", &templates.LoginPage{false, ""})
		case "POST":
			r.ParseForm()
			log.Println(r.Form)

			user, uuid, loginErr := db.LogUserIn(strings.Join(r.Form["username"], ""), strings.Join(r.Form["password"], ""))
			log.Println(user, uuid, loginErr)

			if loginErr != nil {
				w.WriteHeader(http.StatusUnauthorized)
			}else {
				authTokenString, refreshTokenString, csrfSecret, err := myjwt.CreateNewTokens(uuid, user.Role)
				if err != nil{
					http.Error(w, http.StatusText(500),500)
				}
				setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
				w.WriteHeader((http.StatusOK))
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case "/register":
		switch r.Method {
		case "GET":
			templates.RenderTemplate(w, "register", &templates.RegisterPage{false,""})
		case "POST":
			r.ParseForm()
			log.Println(r.Form)

			_, uuid, err :=  db.FetchUserByUsername(strings.Join(r.Form["username"], ""))
			if err == nil{
				w.WriteHeader(http.StatusUnauthorized)
			} else {
				role := "user"
				uuid, err = db.StoreUser(strings.Join(r.Form["username"], ""), strings.Join(r.Form["password"], ""), role)
				if err != nil {
					http.Error(w, http.StatusText(500), 500)
				}
				log.Println("uuid:" + uuid)
				authTokenString, refreshTokenString, csrfSecret, err := myjwt.CreateNewTokens(uuid, role)
				if err != nil {
					http.Error(w, http.StatusText(500), 500)
				}
				setAuthAndRefreshCookies(&w, authTokenString, refreshTokenString)
				w.Header().Set("X-CSRF-TOKEN", csrfSecret)
				w.WriteHeader(http.StatusOK)
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case "/logout":
		nullifyTokenCookies(&w, r)
		http.Redirect(w,r, "/login", 302)
	case "/deleteUser":
		log.Println("Kullanıcıyı silme")
		AuthCookie, authErr := r.Cookie("AuthToken")
		if authErr == http.ErrNoCookie{
			log.Println("Yetkisiz deneme! auth çerezi yok")
			nullifyTokenCookies(&w, r)
			http.Redirect(w,r, "/login", 302)
			return
		}else if authErr != nil{
			log.Panic("panic:%+v", authErr)
			nullifyTokenCookies(&w,r)
			http.Error(w,http.StatusText(500),500)
			return
		}

		uuid, uuidErr := myjwt.GrabUUID(AuthCookie.Value)
		if uuidErr != nil{
			log.Panic("panic:%+v", uuidErr)
			nullifyTokenCookies(&w, r)
			http.Error(w, http.StatusText(500),500)
			return
		}
		db.DeleteUser(uuid)
		nullifyTokenCookies(&w, r)
		http.Redirect(w, r, "/register", 302)
	default:
		w.WriteHeader(http.StatusOK)
	}
}

func nullifyTokenCookies(w *http.ResponseWriter, r *http.Request) {
	authCookie := http.Cookie{
		Name:     "AuthToken",
		Value:    "",
		Expires:  time.Now().Add(-1000 * time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(*w, &authCookie)

	refreshCookie := http.Cookie{
		Name:     "RefreshToken",
		Value:    "",
		Expires:  time.Now().Add(-1000 * time.Hour),
		HttpOnly: true,
	}
	http.SetCookie(*w, &refreshCookie)

	RefreshCookie, refreshErr := r.Cookie("RefreshToken")
	if refreshErr == http.ErrNoCookie{
		//hiçbir şey yapma
		return
	}else if refreshErr != nil {
		log.Panic("panic: %+v", refreshErr)
		http.Error(*w, http.StatusText(500), 500)
	}

	myjwt.RevokeRefreshToken(RefreshCookie.Value)
}

func setAuthAndRefreshCookies(w *http.ResponseWriter, authTokenString string, refreshTokenString string) {
	authCookie := http.Cookie{
		Name:     "AuthToken",
		Value:    authTokenString,
		HttpOnly: true,
	}

	http.SetCookie(*w, &authCookie)
	refreshCookie := http.Cookie{
		Name:  "RefreshToken",
		Value: refreshTokenString,
		HttpOnly: true,
	}

	http.SetCookie(*w, &refreshCookie)
}

func grabCsrfFromReq(r *http.Request) string {
	csrfFromFrom := r.FormValue("X-CSRF-TOKEN")

	if csrfFromFrom != "" {
		return csrfFromFrom
	} else {
		return r.Header.Get("X-CSRF-TOKEN")
	}
}
