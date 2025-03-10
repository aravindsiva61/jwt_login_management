package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"

	"fmt"
	"math/rand"
	"net/smtp"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

// Login page handler to validate login and store jwt cookie
func LoginPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		var storedPassword, role string
		err := db.QueryRow("SELECT password, role FROM users WHERE username = ?", username).Scan(&storedPassword, &role)
		if err == sql.ErrNoRows {
			http.Redirect(w, r, "/register", http.StatusSeeOther)
			return
		} else if err != nil || bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password)) != nil {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}

		token, err := GenerateJWT(username)
		if err != nil {
			http.Error(w, "Error generating token", http.StatusInternalServerError)
			return
		}

		// Store the token in an HTTP-only cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "auth_token",
			Value:    token,
			Expires:  time.Now().Add(time.Hour * 24),
			HttpOnly: true,
			Path:     "/",
		})

		htmlResponse := fmt.Sprintf(`
		<!DOCTYPE html>
		<html lang="en">
		<head>
			<meta charset="UTF-8">
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
			<title>Login Success</title>
			<style>
				body {
					display: flex;
					justify-content: center;
					align-items: center;
					height: 100vh;
					margin: 0;
					font-family: Arial, sans-serif;
					background-color: #f4f4f4;
				}
				.container {
					text-align: center;
					background: white;
					padding: 20px;
					box-shadow: 0px 4px 6px rgba(0, 0, 0, 0.1);
					border-radius: 10px;
				}
				h1 {
					color: #4CAF50;
				}
				p {
					color: #333;
				}
			</style>
		</head>
		<body>
			<div class="container">
				<h1>User Login Successful!</h1>
				<p>Email: %s</p>
			</div>
		</body>
		</html>
	`, username)

		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(htmlResponse))
		return
	}
	templates.ExecuteTemplate(w, "login.html", nil)
}

// Helper function to ensure password length is more than 8 characters and contain 1 character and 1 number
func ValidatePassword(password string) bool {

	// Ensure password has at least one digit, one special character, and is at least 8 characters long
	re := regexp.MustCompile(`^[A-Za-z\d!@#$%^&*()_+\-=\[\]{}|;:'",.<>?/]{8,}$`)
	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(password)
	hasSpecial := regexp.MustCompile(`[!@#$%^&*()_+\-=\[\]{}|;:'",.<>?/]+`).MatchString(password)

	return re.MatchString(password) && hasNumber && hasSpecial

}

// Register page handler to register user, update them in database and also check password is valid
func RegisterPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")
		retypePassword := r.FormValue("retype_password")

		if !ValidatePassword(password) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Password must be at least 8 characters long and include 1 special character and 1 number"})
			return
		}

		if password != retypePassword {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Passwords do not match"})
			return
		}

		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

		_, err := db.Exec("INSERT INTO users (username, password) VALUES (?, ?)", username, hashedPassword)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			json.NewEncoder(w).Encode(map[string]string{"error": "User already exists"})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"success": "Registration successful"})
		return
	}

	templates.ExecuteTemplate(w, "register.html", nil)
}

var jwtSecret = []byte("jwt_token")

// Helper function to generate jwt token
func GenerateJWT(username string) (string, error) {
	claims := jwt.MapClaims{
		"username": username,
		"exp":      time.Now().Add(time.Hour * 24).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

// Admin page to validate admin credentials
func AdminPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		username := r.FormValue("username")
		password := r.FormValue("password")

		var storedPassword string
		err := db.QueryRow("SELECT password FROM users WHERE username = ? AND role = 'admin'", username).Scan(&storedPassword)
		if err != nil || bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password)) != nil {
			http.Error(w, "Invalid admin credentials", http.StatusUnauthorized)
			return
		}
		token, err := GenerateJWT(username)
		if err != nil {
			http.Error(w, "Error generating token", http.StatusInternalServerError)
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "auth_token",
			Value:    token,
			Expires:  time.Now().Add(time.Hour * 24),
			HttpOnly: true,
			Path:     "/",
		})

		// Redirect to Admin Dashboard
		http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
		return
	}

	templates.ExecuteTemplate(w, "admin_login.html", nil)
}

// Validates JWT token read from cookie
func ValidateJWT(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		cookie, err := r.Cookie("auth_token")
		if err != nil {
			http.Error(w, "No token provided", http.StatusUnauthorized)
			return
		}

		tokenString := cookie.Value
		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		next(w, r)
	}
}

// Admin dashboard to fetch all user from database and display them
func AdminDashboard(w http.ResponseWriter, r *http.Request) {
	// Fetch all non-admin users
	rows, _ := db.Query("SELECT id, username FROM users WHERE role != 'admin'")
	defer rows.Close()

	var users []struct {
		ID       int
		Username string
	}
	for rows.Next() {
		var u struct {
			ID       int
			Username string
		}
		rows.Scan(&u.ID, &u.Username)
		users = append(users, u)
	}

	templates.ExecuteTemplate(w, "admin.html", users)
}

// Function to update user details in database
func UpdateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	id := r.FormValue("id")
	newUsername := r.FormValue("username")

	if id == "" || newUsername == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	_, err := db.Exec("UPDATE users SET username = ? WHERE id = ?", newUsername, id)
	if err != nil {
		http.Error(w, "Error updating user", http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
}

// Function to delete user from database
func DeleteUser(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.FormValue("id"))
	_, _ = db.Exec("DELETE FROM users WHERE id=?", id)
	http.Redirect(w, r, "/admin/dashboard", http.StatusSeeOther)
}

// Forgot password handler to check if user is in database and generate token and send the reset passowrd link to email
func ForgotPasswordPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		email := r.FormValue("email")

		var userID int
		err := db.QueryRow("SELECT id FROM users WHERE username = ?", email).Scan(&userID)
		if err == sql.ErrNoRows {
			http.Error(w, "User not found", http.StatusNotFound)
			return
		} else if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}

		token := generateResetToken()

		// Store the token in the database with expiration time
		_, err = db.Exec("INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, DATETIME('now', '+1 hour'))", userID, token)
		if err != nil {
			http.Error(w, "Could not generate reset token", http.StatusInternalServerError)
			return
		}

		resetLink := "http://localhost:8080/reset-password?token=" + token
		sendEmail(email, resetLink)

		w.Write([]byte("Password reset link has been sent to your email."))
		return
	}
	templates.ExecuteTemplate(w, "forgot_password.html", nil)
}

// Helper function to generate reset password token
func generateResetToken() string {
	rand.Seed(time.Now().UnixNano())
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 20)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// Helper function to send email using SMTP
func sendEmail(to, resetLink string) {
	from := "aravindshiva61@gmail.com"
	password := "ueyy ziuj zixb jizn"

	smtpServer := "smtp.gmail.com"
	port := "587"

	msg := "Subject: Password Reset\n\nClick the link to reset your password: " + resetLink
	auth := smtp.PlainAuth("", from, password, smtpServer)

	err := smtp.SendMail(smtpServer+":"+port, auth, from, []string{to}, []byte(msg))
	if err != nil {
		fmt.Println("Email send error:", err)
	} else {
		fmt.Println("Email sent successfully!")
	}
}

// Function to validate token in reset password link and update the password in database
func ResetPasswordPage(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {

		token := r.URL.Query().Get("token")
		//fmt.Println("Received Token from URL (GET):", token)

		if token == "" {
			http.Error(w, "No token provided", http.StatusBadRequest)
			return
		}

		// Render the reset password page with the token
		templates.ExecuteTemplate(w, "reset_password.html", map[string]string{"Token": token})
		return
	}

	if r.Method == http.MethodPost {

		token := r.FormValue("token")
		//fmt.Println("Received Token in POST:", token)

		if token == "" {
			http.Error(w, "No token provided", http.StatusBadRequest)
			return
		}

		newPassword := r.FormValue("password")
		retypePassword := r.FormValue("retype_password")

		if newPassword != retypePassword {
			http.Error(w, "Passwords do not match", http.StatusBadRequest)
			return
		}

		var userID int
		err := db.QueryRow("SELECT user_id FROM password_resets WHERE token = ?", token).Scan(&userID)

		if err == sql.ErrNoRows {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		} else if err != nil {
			http.Error(w, "Database error", http.StatusInternalServerError)
			return
		}

		hashedPassword, _ := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)

		_, err = db.Exec("UPDATE users SET password = ? WHERE id = ?", hashedPassword, userID)
		if err != nil {
			http.Error(w, "Error updating password", http.StatusInternalServerError)
			return
		}

		// Remove used reset token
		_, _ = db.Exec("DELETE FROM password_resets WHERE user_id = ?", userID)

		w.Write([]byte("Password successfully reset. You can now log in."))
	}
}
