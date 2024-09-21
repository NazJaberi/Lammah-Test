package lammah

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/csrf"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/go-playground/validator.v9"
)

var validate *validator.Validate

type contextKey string

const userIDKey contextKey = "user_id"

type User struct {
	ID             int64     `json:"id"`
	FirstName      string    `json:"firstName" validate:"required,min=2,max=50"`
	LastName       string    `json:"lastName" validate:"required,min=2,max=50"`
	DateOfBirth    time.Time `json:"dateOfBirth" validate:"required,ltefield=Today"`
	Email          string    `json:"email" validate:"required,email"`
	PhoneNumber    string    `json:"phoneNumber" validate:"required,e164"`
	ParentNumber   string    `json:"parentNumber" validate:"omitempty,e164"`
	Password       string    `json:"password" validate:"required,min=8"`
	Username       string    `json:"username" validate:"required,min=3,max=50"`
}

type Session struct {
	Token     string
	UserID    int64
	ExpiresAt time.Time
}

func init() {
	validate = validator.New()
	validate.RegisterValidation("ltefield", validateLessThanEqual)
}

func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user.DateOfBirth = user.DateOfBirth.UTC() // Ensure UTC time
	if err := validate.Struct(user); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Check if user is under 18 and parent number is provided
	if getAge(user.DateOfBirth) < 18 && user.ParentNumber == "" {
		http.Error(w, "Parent number is required for users under 18", http.StatusBadRequest)
		return
	}

	exists, err := userExists(user.Username, user.Email)
	if err != nil {
		log.Printf("Database error during registration: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	if exists {
		http.Error(w, "Username or email already exists", http.StatusConflict)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	userID, err := createUser(user, string(hashedPassword))
	if err != nil {
		log.Printf("Error creating user: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	sessionToken, err := createSession(userID)
	if err != nil {
		log.Printf("Error creating session: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	setSessionCookie(w, sessionToken)

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully"})
}

func LoginHandler(w http.ResponseWriter, r *http.Request) {
	var credentials struct {
		Username string `json:"username" validate:"required"`
		Password string `json:"password" validate:"required"`
	}

	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := validate.Struct(credentials); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, hashedPassword, err := getUserByUsername(credentials.Username)
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(credentials.Password)); err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	if err := deleteExistingSessions(user.ID); err != nil {
		log.Printf("Error deleting existing sessions: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	sessionToken, err := createSession(user.ID)
	if err != nil {
		log.Printf("Error creating session: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	setSessionCookie(w, sessionToken)

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Login successful"})
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session_token")
	if err != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	if err := deleteSession(c.Value); err != nil {
		log.Printf("Error deleting session: %v", err)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Now().Add(-1 * time.Hour),
		MaxAge:   -1,
	})

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Logout successful"})
}

func setSessionCookie(w http.ResponseWriter, sessionToken string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session_token",
		Value:    sessionToken,
		Expires:  time.Now().Add(24 * time.Hour),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})
}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("session_token")
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		session, err := getSession(c.Value)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if time.Now().After(session.ExpiresAt) {
			deleteSession(c.Value)
			http.Error(w, "Session expired", http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), userIDKey, session.UserID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func SetupRoutes(r *mux.Router) {
	r.HandleFunc("/register", RegisterHandler).Methods("POST")
	r.HandleFunc("/login", LoginHandler).Methods("POST")
	r.HandleFunc("/logout", LogoutHandler).Methods("POST")

	csrfMiddleware := csrf.Protect([]byte(os.Getenv("CSRF_KEY")), csrf.Secure(true))
	r.Use(csrfMiddleware)
}

func validateLessThanEqual(fl validator.FieldLevel) bool {
	date, ok := fl.Field().Interface().(time.Time)
	if !ok {
		return false
	}

	now := time.Now()
	return date.Before(now) || date.Equal(now)
}

func getAge(birthDate time.Time) int {
	now := time.Now()
	age := now.Year() - birthDate.Year()
	if now.YearDay() < birthDate.YearDay() {
		age--
	}
	return age
}