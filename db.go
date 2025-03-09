package main

import (
	"database/sql"
	"log"

	_ "modernc.org/sqlite"
)

var db *sql.DB

// Iniitialize user and password reset table and insert admin credentials
func InitDB() {
	var err error
	db, err = sql.Open("sqlite", "./users.db")
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password TEXT NOT NULL,
		role TEXT NOT NULL DEFAULT 'user'
	);
	`)
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL UNIQUE,
    expires_at DATETIME NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
	`)
	if err != nil {
		log.Fatal(err)
	}

	_, err = db.Exec(`INSERT OR IGNORE INTO users (username, password, role) VALUES ('admin', '$2a$10$1MrCAHdeEET36hUuraYg9uPC825mBPN13N0Bbdivhq5Oqa8Bl/6ki', 'admin')`)
	if err != nil {
		log.Fatal(err)
	}
}
