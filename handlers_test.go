package main

import (
	"bytes"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

// Setup mock database for testing
func setupTestDB() {
	db, _ = sql.Open("sqlite", ":memory:") // In-memory DB for testing

	// Create users table
	db.Exec(`CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		role TEXT NOT NULL DEFAULT 'user'
	);`)

	// Create password reset table
	db.Exec(`CREATE TABLE password_resets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		token TEXT NOT NULL UNIQUE,
		expires_at DATETIME NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id)
	);`)

	// Insert test user (password: "password123")
	hashedPassword, _ := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	db.Exec(`INSERT INTO users (username, password, role) VALUES ('testuser', ?, 'user')`, hashedPassword)

	// Insert test admin
	db.Exec(`INSERT INTO users (username, password, role) VALUES ('admin', ?, 'admin')`, hashedPassword)
}

func TestLoginPage(t *testing.T) {
	setupTestDB()

	// Test successful login
	t.Run("Successful Login", func(t *testing.T) {
		formData := "username=testuser&password=password123"
		req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBufferString(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		LoginPage(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
	})

	// Test incorrect credentials
	t.Run("Invalid Credentials", func(t *testing.T) {
		formData := "username=testuser&password=wrongpass"
		req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBufferString(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		LoginPage(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", resp.StatusCode)
		}
	})
}

// Test valid passowrd containing more than 8 characters with 1 special character and 1 number
func TestValidPassword(t *testing.T) {
	if !ValidatePassword("Password@123") {
		t.Errorf("Expected valid password, but got invalid")
	}
}

// Test invalid passowrd whuch does not contain more than 8 characters with 1 special character and 1 number
func TestInvalidPassword(t *testing.T) {
	if ValidatePassword("Password123") {
		t.Errorf("Expected invalid password, but got valid")
	}
}

func TestRegisterPage(t *testing.T) {
	setupTestDB()

	//Test successful registration
	t.Run("Successful Registration", func(t *testing.T) {
		formData := "username=newuser&password=password@123&retype_password=password@123"
		req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBufferString(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		RegisterPage(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
	})

	// Test duplicate user
	t.Run("Duplicate User Registration", func(t *testing.T) {
		formData := "username=testuser&password=password@123&retype_password=password@123"
		req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewBufferString(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		RegisterPage(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusConflict {
			t.Errorf("Expected status 409, got %d", resp.StatusCode)
		}
	})
}

func TestAdminPage(t *testing.T) {
	setupTestDB()

	// Test successful admin login
	t.Run("Successful Admin Login", func(t *testing.T) {
		formData := "username=admin&password=password123"
		req := httptest.NewRequest(http.MethodPost, "/admin", bytes.NewBufferString(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		AdminPage(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusSeeOther {
			t.Errorf("Expected status 303, got %d", resp.StatusCode)
		}
	})

	// Test invalid admin credentials
	t.Run("Invalid Admin Login", func(t *testing.T) {
		formData := "username=admin&password=wrongpass"
		req := httptest.NewRequest(http.MethodPost, "/admin", bytes.NewBufferString(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		AdminPage(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", resp.StatusCode)
		}
	})
}

func TestForgotPasswordPage(t *testing.T) {
	setupTestDB()

	// Test sending reset email
	t.Run("Successful Reset Email", func(t *testing.T) {
		formData := "email=testuser"
		req := httptest.NewRequest(http.MethodPost, "/forgot-password", bytes.NewBufferString(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		ForgotPasswordPage(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
	})

	// Test non-existent user
	t.Run("User Not Found", func(t *testing.T) {
		formData := "email=notexist"
		req := httptest.NewRequest(http.MethodPost, "/forgot-password", bytes.NewBufferString(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		ForgotPasswordPage(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("Expected status 404, got %d", resp.StatusCode)
		}
	})
}

func TestResetPasswordPage(t *testing.T) {
	setupTestDB()

	// Insert a test password reset token
	token := "validtoken"
	db.Exec(`INSERT INTO password_resets (user_id, token, expires_at) VALUES (1, ?, DATETIME('now', '+1 hour'))`, token)

	// Test successful password reset
	t.Run("Successful Password Reset", func(t *testing.T) {
		formData := "token=validtoken&password=newpass&retype_password=newpass"
		req := httptest.NewRequest(http.MethodPost, "/reset-password", bytes.NewBufferString(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		ResetPasswordPage(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status 200, got %d", resp.StatusCode)
		}
	})

	// Test invalid token
	t.Run("Invalid Token", func(t *testing.T) {
		formData := "token=invalidtoken&password=newpass&retype_password=newpass"
		req := httptest.NewRequest(http.MethodPost, "/reset-password", bytes.NewBufferString(formData))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()

		ResetPasswordPage(w, req)

		resp := w.Result()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("Expected status 401, got %d", resp.StatusCode)
		}
	})
}
