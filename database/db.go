package database

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"log"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jmoiron/sqlx"
	_ "modernc.org/sqlite" // The CGO-free SQLite driver
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// DB is the global connection pool for the application. It is initialized by InitDB.
var DB *sqlx.DB

// InitDB initializes the SQLite database connection, runs migrations, and sets up the global DB variable.
func InitDB(dbPath string) error {
	// The `_pragma=foreign_keys(1)` is crucial for enforcing data integrity.
	db, err := sqlx.Open("sqlite", dbPath+"?_pragma=foreign_keys(1)")
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	if err = db.Ping(); err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}

	DB = db
	//log.Println("Database connection established.")

	// Run database migrations
	if err := runMigrations(db.DB); err != nil {
		return fmt.Errorf("database migration failed: %w", err)
	}

	return nil
}

// runMigrations applies all pending database migrations.
func runMigrations(db *sql.DB) error {
	sourceDriver, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("failed to create migration source driver: %w", err)
	}

	dbDriver, err := sqlite.WithInstance(db, &sqlite.Config{})
	if err != nil {
		return fmt.Errorf("failed to create migration database driver: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", sourceDriver, "sqlite", dbDriver)
	if err != nil {
		return fmt.Errorf("failed to create migrate instance: %w", err)
	}

	// Get current version to see if we need to do anything
	version, dirty, err := m.Version()
	if err != nil && !errors.Is(err, migrate.ErrNilVersion) {
		return fmt.Errorf("could not get db version: %w", err)
	}
	if dirty {
		return fmt.Errorf("database is in a dirty state (version %d). Please fix manually or delete the db file", version)
	}

	//log.Printf("Current database version: %d\n", version)

	// Apply all available "up" migrations.
	err = m.Up()
	if err != nil {
		// The only acceptable error is "no change". Anything else is a real problem.
		if errors.Is(err, migrate.ErrNoChange) {
			log.Println("Database schema is up-to-date.")
		} else {
			// This will now catch any other migration error and report it,
			// causing the application to exit correctly.
			return fmt.Errorf("failed to apply migrations: %w", err)
		}
	} else {
		log.Println("Database migrations applied successfully.")
	}

	return nil
}
