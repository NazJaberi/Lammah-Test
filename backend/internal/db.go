package lammah

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
)

var db *sql.DB

func init() {
	var err error
	
	// Connect to MySQL server without specifying a database
	db, err = sql.Open("mysql", os.Getenv("DB_CONNECTION_STRING"))
	if err != nil {
		log.Fatalf("Failed to connect to MySQL server: %v", err)
	}

	// Create the database if it doesn't exist
	_, err = db.Exec("CREATE DATABASE IF NOT EXISTS lammah")
	if err != nil {
		log.Fatalf("Failed to create database: %v", err)
	}

	// Close the connection and reconnect to the specific database
	db.Close()
	db, err = sql.Open("mysql", os.Getenv("DB_CONNECTION_STRING") + "/lammah")
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	if err = db.Ping(); err != nil {
		log.Fatalf("Failed to ping database: %v", err)
	}

	if err := createTables(); err != nil {
		log.Fatalf("Failed to create tables: %v", err)
	}
}

func createTables() error {
	// Create users table if not exists
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INT AUTO_INCREMENT PRIMARY KEY,
			first_name VARCHAR(50) NOT NULL,
			last_name VARCHAR(50) NOT NULL,
			date_of_birth DATE NOT NULL,
			email VARCHAR(100) UNIQUE NOT NULL,
			phone_number VARCHAR(20) NOT NULL,
			parent_number VARCHAR(20),
			password VARCHAR(255) NOT NULL,
			username VARCHAR(50) UNIQUE NOT NULL
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create users table: %v", err)
	}

	// Create sessions table if not exists
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS sessions (
			token VARCHAR(36) PRIMARY KEY,
			user_id INT NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)
	`)
	if err != nil {
		return fmt.Errorf("failed to create sessions table: %v", err)
	}

	return nil
}

func userExists(username, email string) (bool, error) {
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE username = ? OR email = ?)", username, email).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("failed to check if user exists: %v", err)
	}
	return exists, nil
}

func createUser(user User, hashedPassword string) (int64, error) {
	result, err := db.Exec(`
		INSERT INTO users (first_name, last_name, date_of_birth, email, phone_number, parent_number, password, username) 
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		user.FirstName, user.LastName, user.DateOfBirth, user.Email, user.PhoneNumber, user.ParentNumber, hashedPassword, user.Username)
	if err != nil {
		return 0, fmt.Errorf("failed to create user: %v", err)
	}
	return result.LastInsertId()
}

func getUserByUsername(username string) (User, string, error) {
	var user User
	var hashedPassword string
	err := db.QueryRow("SELECT id, username, password FROM users WHERE username = ?", username).
		Scan(&user.ID, &user.Username, &hashedPassword)
	if err != nil {
		return User{}, "", fmt.Errorf("failed to get user by username: %v", err)
	}
	return user, hashedPassword, nil
}

func createSession(userID int64) (string, error) {
	sessionToken := uuid.New().String()
	expiresAt := time.Now().Add(24 * time.Hour)

	_, err := db.Exec("INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
		sessionToken, userID, expiresAt)
	if err != nil {
		return "", fmt.Errorf("failed to create session: %v", err)
	}

	return sessionToken, nil
}

func deleteExistingSessions(userID int64) error {
	_, err := db.Exec("DELETE FROM sessions WHERE user_id = ?", userID)
	if err != nil {
		return fmt.Errorf("failed to delete existing sessions: %v", err)
	}
	return nil
}

func deleteSession(sessionToken string) error {
	_, err := db.Exec("DELETE FROM sessions WHERE token = ?", sessionToken)
	if err != nil {
		return fmt.Errorf("failed to delete session: %v", err)
	}
	return nil
}

func getSession(sessionToken string) (Session, error) {
	var session Session
	err := db.QueryRow("SELECT token, user_id, expires_at FROM sessions WHERE token = ?", sessionToken).
		Scan(&session.Token, &session.UserID, &session.ExpiresAt)
	if err != nil {
		return Session{}, fmt.Errorf("failed to get session: %v", err)
	}
	return session, nil
}