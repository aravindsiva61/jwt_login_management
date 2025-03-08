package main

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"
)

// TestInitDB checks if the database initializes properly
func TestInitDB(t *testing.T) {
	var err error

	// Use in-memory database for testing (won't persist)
	db, err = sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("Failed to open test database: %v", err)
	}

	// Ensure database initializes without errors
	InitDB()

	// Check if the "users" table exists
	if !tableExists("users") {
		t.Errorf("Table 'users' does not exist")
	}

	// Check if the "password_resets" table exists
	if !tableExists("password_resets") {
		t.Errorf("Table 'password_resets' does not exist")
	}

	// Check if the admin user was inserted
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM users WHERE username = 'admin'").Scan(&count)
	if err != nil {
		t.Errorf("Error querying admin user: %v", err)
	} else if count == 0 {
		t.Errorf("Admin user was not inserted into the database")
	}

	// Close the test database
	db.Close()
}

// Helper function to check if a table exists in the database
func tableExists(tableName string) bool {
	query := "SELECT name FROM sqlite_master WHERE type='table' AND name=?"
	var name string
	err := db.QueryRow(query, tableName).Scan(&name)
	return err == nil
}
