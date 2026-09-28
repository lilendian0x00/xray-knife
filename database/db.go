package database

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite"
	"github.com/golang-migrate/migrate/v4/source"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jmoiron/sqlx"
	"github.com/lilendian0x00/xray-knife/v11/utils/customlog"
	"github.com/lilendian0x00/xray-knife/v11/utils/xkhome"
	_ "modernc.org/sqlite" // The CGO-free SQLite driver
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// DB is the global connection pool for the application. It is set by InitDB,
// or opened lazily by Conn on first use.
var DB *sqlx.DB

var (
	connMu       sync.Mutex
	pathResolver func() (string, error)
)

// SetPathResolver registers how Conn finds the database file. The database
// is opened (and migrated) on first use rather than at startup, so commands
// that never touch it (parse, completion, --help) never create or migrate
// it. Without a resolver Conn uses the default location under
// XRAY_KNIFE_HOME.
func SetPathResolver(fn func() (string, error)) {
	connMu.Lock()
	defer connMu.Unlock()
	pathResolver = fn
}

// ResolvePath returns the database path Conn would open, without opening it.
func ResolvePath() (string, error) {
	connMu.Lock()
	fn := pathResolver
	connMu.Unlock()
	if fn == nil {
		return xkhome.DBPath("")
	}
	return fn()
}

// Conn returns the open database, opening and migrating it on first use. It
// is safe for concurrent use.
func Conn() (*sqlx.DB, error) {
	connMu.Lock()
	defer connMu.Unlock()
	if DB != nil {
		return DB, nil
	}
	fn := pathResolver
	if fn == nil {
		fn = func() (string, error) { return xkhome.DBPath("") }
	}
	path, err := fn()
	if err != nil {
		return nil, fmt.Errorf("could not resolve the database path: %w", err)
	}
	db, err := openAndMigrate(path)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database %s: %w", path, err)
	}
	DB = db
	return DB, nil
}

// InitDB opens the SQLite connection, runs migrations, and sets the global DB.
func InitDB(dbPath string) error {
	db, err := openAndMigrate(dbPath)
	if err != nil {
		return err
	}
	connMu.Lock()
	DB = db
	connMu.Unlock()
	return nil
}

// Close closes the global connection, if open.
func Close() error {
	connMu.Lock()
	defer connMu.Unlock()
	if DB == nil {
		return nil
	}
	err := DB.Close()
	DB = nil
	return err
}

// dsnParams are appended to every DSN:
//   - foreign_keys: enforce data integrity
//   - busy_timeout: wait instead of failing immediately on lock contention
//   - journal_mode=WAL: allow concurrent reads during writes
//   - _txlock=immediate: write transactions take the write lock up front,
//     so two writers queue on busy_timeout instead of deadlocking on a
//     read-to-write upgrade (which SQLite reports as SQLITE_BUSY at once)
//   - _time_format=sqlite: write time.Time as a parseable RFC-style string
//     instead of t.String() (unparseable in zones with numeric abbreviations
//     like "+0330")
const dsnParams = "_pragma=foreign_keys(1)&_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_txlock=immediate&_time_format=sqlite"

func isMemoryPath(p string) bool {
	return p == ":memory:" || strings.HasPrefix(p, "file::memory:")
}

// buildDSN turns a filesystem path into a modernc.org/sqlite DSN. The driver
// cuts a plain DSN at the first '?', so a path containing one is passed as a
// file: URI with the path percent-encoded instead.
func buildDSN(p string) string {
	switch {
	case isMemoryPath(p) || strings.HasPrefix(p, "file:"):
		sep := "?"
		if strings.Contains(p, "?") {
			sep = "&"
		}
		return p + sep + dsnParams
	case strings.Contains(p, "?"):
		return fileURI(p) + "?" + dsnParams
	default:
		return p + "?" + dsnParams
	}
}

// fileURI renders p as an SQLite file: URI.
func fileURI(p string) string {
	p = filepath.ToSlash(p)
	if runtime.GOOS == "windows" && filepath.VolumeName(p) != "" {
		p = "/" + p // file:///C:/dir/x.db
	}
	var b strings.Builder
	b.WriteString("file:")
	if strings.HasPrefix(p, "/") && runtime.GOOS == "windows" {
		b.WriteString("//")
	}
	for i := 0; i < len(p); i++ {
		switch c := p[i]; c {
		case '?', '#', '%':
			fmt.Fprintf(&b, "%%%02X", c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// prepareFile checks the database's directory and creates a missing
// database file with mode 0600 (it stores subscription URLs), before SQLite
// would create it with the umask default.
func prepareFile(p string) error {
	if isMemoryPath(p) || strings.HasPrefix(p, "file:") {
		return nil
	}
	dir := filepath.Dir(p)
	info, err := os.Stat(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("database directory %s does not exist (create it, or pick another --db path)", dir)
		}
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("database directory %s is not a directory", dir)
	}
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if os.IsExist(err) {
			return nil
		}
		return fmt.Errorf("could not create database file: %w", err)
	}
	return f.Close()
}

func openAndMigrate(dbPath string) (*sqlx.DB, error) {
	if err := prepareFile(dbPath); err != nil {
		return nil, err
	}
	db, err := sqlx.Open("sqlite", buildDSN(dbPath))
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	if err := pingWithRetry(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}
	if err := migrateUp(db.DB, dbPath); err != nil {
		db.Close()
		return nil, fmt.Errorf("database migration failed: %w", err)
	}
	if !isMemoryPath(dbPath) {
		xkhome.ChownToInvoker(dbPath, dbPath+"-wal", dbPath+"-shm", lockPath(dbPath))
	}
	return db, nil
}

// OpenNoMigrate opens dbPath without running migrations, for maintenance
// commands that must work on a database whose migration state is broken.
func OpenNoMigrate(dbPath string) (*sqlx.DB, error) {
	if err := prepareFile(dbPath); err != nil {
		return nil, err
	}
	db, err := sqlx.Open("sqlite", buildDSN(dbPath))
	if err != nil {
		return nil, err
	}
	if err := pingWithRetry(db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// OpenReadOnly opens an existing database read-only, without migrations.
// It returns (nil, nil) when the file does not exist. Shell completion uses
// it so pressing TAB never creates or migrates anything.
func OpenReadOnly(dbPath string) (*sqlx.DB, error) {
	if isMemoryPath(dbPath) {
		return nil, nil
	}
	if !strings.HasPrefix(dbPath, "file:") {
		if _, err := os.Stat(dbPath); err != nil {
			if os.IsNotExist(err) {
				return nil, nil
			}
			return nil, err
		}
		dbPath = fileURI(dbPath)
	}
	sep := "?"
	if strings.Contains(dbPath, "?") {
		sep = "&"
	}
	db, err := sqlx.Open("sqlite", dbPath+sep+"mode=ro&_pragma=busy_timeout(2000)&_time_format=sqlite")
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func isBusy(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "SQLITE_BUSY") || strings.Contains(msg, "database is locked")
}

// pingWithRetry opens the first connection. Switching to WAL needs a brief
// write lock, which another xray-knife process starting at the same moment
// may hold longer than busy_timeout covers on slow disks.
func pingWithRetry(db *sqlx.DB) error {
	var err error
	delay := 100 * time.Millisecond
	for attempt := 0; attempt < 5; attempt++ {
		if err = db.Ping(); err == nil || !isBusy(err) {
			return err
		}
		time.Sleep(delay)
		delay *= 2
	}
	return err
}

func lockPath(dbPath string) string { return dbPath + ".lock" }

var errLockBusy = errors.New("lock held by another process")

// acquireMigrationLock serialises migrations across processes with an
// advisory lock on "<db>.lock". Without it, several xray-knife processes
// started at once on a fresh database each try to create the schema, and
// the losers leave schema_migrations marked dirty for good.
func acquireMigrationLock(dbPath string, timeout time.Duration) (func(), error) {
	if isMemoryPath(dbPath) || strings.HasPrefix(dbPath, "file:") {
		return func() {}, nil
	}
	f, err := os.OpenFile(lockPath(dbPath), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("could not open migration lock: %w", err)
	}
	deadline := time.Now().Add(timeout)
	for {
		err = tryLockFile(f)
		if err == nil {
			return func() {
				_ = unlockFile(f)
				_ = f.Close()
			}, nil
		}
		if !errors.Is(err, errLockBusy) {
			f.Close()
			return nil, fmt.Errorf("could not take migration lock: %w", err)
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, fmt.Errorf("timed out after %s waiting for another xray-knife process to finish migrating %s", timeout, dbPath)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func newMigrator(db *sql.DB) (*migrate.Migrate, source.Driver, error) {
	sourceDriver, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create migration source driver: %w", err)
	}
	dbDriver, err := sqlite.WithInstance(db, &sqlite.Config{})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create migration database driver: %w", err)
	}
	m, err := migrate.NewWithInstance("iofs", sourceDriver, "sqlite", dbDriver)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create migrate instance: %w", err)
	}
	return m, sourceDriver, nil
}

// LatestVersion is the newest schema version embedded in this binary.
func LatestVersion() (uint, error) {
	src, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return 0, err
	}
	defer src.Close()
	return latestSourceVersion(src)
}

func latestSourceVersion(src source.Driver) (uint, error) {
	v, err := src.First()
	if err != nil {
		return 0, err
	}
	for {
		next, err := src.Next(v)
		if errors.Is(err, os.ErrNotExist) {
			return v, nil
		}
		if err != nil {
			return 0, err
		}
		v = next
	}
}

// migrateUp applies pending migrations under the cross-process lock.
func migrateUp(db *sql.DB, dbPath string) error {
	unlock, err := acquireMigrationLock(dbPath, 60*time.Second)
	if err != nil {
		return err
	}
	defer unlock()

	m, _, err := newMigrator(db)
	if err != nil {
		return err
	}
	latest, err := LatestVersion()
	if err != nil {
		return err
	}

	version, dirty, err := m.Version()
	if err != nil && !errors.Is(err, migrate.ErrNilVersion) {
		return fmt.Errorf("could not get db version: %w", err)
	}
	if dirty {
		rerun := strconv.Itoa(int(version) - 1)
		if version <= 1 {
			rerun = "none"
		}
		return fmt.Errorf("database is in a dirty state at version %d (a migration was interrupted). "+
			"Back up %s ('xray-knife db backup' works on it), check its schema, then run 'xray-knife db migrate force <version>' "+
			"(%d if that migration's changes are all present, %s to re-run it), or delete the file to start over",
			version, dbPath, version, rerun)
	}
	if err == nil && version >= latest {
		return nil
	}

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("failed to apply migrations: %w", err)
	}
	newVersion, _, verr := m.Version()
	if verr == nil && newVersion != version {
		customlog.Printf(customlog.Info, "Database schema migrated to version %d.\n", newVersion)
		if err == nil && version < sourcesMigration && newVersion >= sourcesMigration {
			customlog.Printf(customlog.Warning, "Configs are now tracked per subscription; the upgrade only knew the last "+
				"subscription of each shared link. Run 'xray-knife subs fetch --all' once so 'subs rm' and --from-db see every source.\n")
		}
	}
	return nil
}

// sourcesMigration is the version that introduced subscription_config_sources.
const sourcesMigration = 3

// MigrationStatus reports the schema version recorded in db.
func MigrationStatus(db *sql.DB) (version uint, dirty bool, err error) {
	m, _, err := newMigrator(db)
	if err != nil {
		return 0, false, err
	}
	version, dirty, err = m.Version()
	if errors.Is(err, migrate.ErrNilVersion) {
		return 0, false, nil
	}
	return version, dirty, err
}

// ForceMigrationVersion records version as applied and clean without running
// any migration: the manual way out of a dirty state.
func ForceMigrationVersion(db *sql.DB, version int) error {
	m, _, err := newMigrator(db)
	if err != nil {
		return err
	}
	return m.Force(version)
}

// conn is the accessor every query uses.
func conn() (*sqlx.DB, error) { return Conn() }

// bg is the context for queries that do not take one.
func bg() context.Context { return context.Background() }
