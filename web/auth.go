package web

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

// bcryptCost is used for newly hashed passwords. Existing hashes keep
// whatever cost they were created with (older builds used 14). A variable
// only so tests can lower it.
var bcryptCost = 12

// tokenTTL is the lifetime of a login token (and of the auth cookie).
const tokenTTL = 24 * time.Hour

// jwtSecret is the HMAC key tokens are signed with. The server derives it
// from the configured secret, the username and the session epoch
// (deriveJWTKey), so changing any of them invalidates every old token.
var jwtSecret []byte

// jwtUsername is the account tokens must name; empty skips the check.
var jwtUsername string

// deriveJWTKey binds the signing key to the account and the session epoch:
// a new username or a bumped epoch (password change) makes every token
// issued before unverifiable.
func deriveJWTKey(secret, username string, epoch uint64) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	fmt.Fprintf(mac, "xray-knife-jwt/v2\x00%s\x00%d", username, epoch)
	return mac.Sum(nil)
}

var (
	errTokenExpired = errors.New("token expired")
	errTokenRevoked = errors.New("token revoked")
)

// AuthDetails holds the credentials for the server.
type AuthDetails struct {
	Username     string
	passwordHash []byte
}

// HashPassword generates a bcrypt hash from a password string.
func (a *AuthDetails) HashPassword(password string) error {
	bytes, err := HashPassword(password)
	if err != nil {
		return err
	}
	a.passwordHash = bytes
	return nil
}

// SetPasswordHash installs an existing bcrypt hash (e.g. from webui.conf).
func (a *AuthDetails) SetPasswordHash(hash string) error {
	if _, err := bcrypt.Cost([]byte(hash)); err != nil {
		return fmt.Errorf("invalid password hash: %w", err)
	}
	a.passwordHash = []byte(hash)
	return nil
}

// HashPassword returns a bcrypt hash of password at the current cost.
func HashPassword(password string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
}

// IsPasswordHash reports whether s looks like a bcrypt hash.
func IsPasswordHash(s string) bool {
	_, err := bcrypt.Cost([]byte(s))
	return err == nil
}

// CheckPassword compares a plaintext password with the stored hash.
func (a *AuthDetails) CheckPassword(password string) bool {
	if a.passwordHash == nil {
		return false
	}
	err := bcrypt.CompareHashAndPassword(a.passwordHash, []byte(password))
	return err == nil
}

// dummyHashes are compared against when the username is wrong, so a wrong
// username costs the same bcrypt work as a wrong password and response time
// does not reveal which usernames exist. One per cost, matching the real hash.
var (
	dummyHashMu sync.Mutex
	dummyHashes = map[int][]byte{}
)

func dummyHashFor(cost int) []byte {
	dummyHashMu.Lock()
	defer dummyHashMu.Unlock()
	if h, ok := dummyHashes[cost]; ok {
		return h
	}
	h, err := bcrypt.GenerateFromPassword([]byte("xray-knife-dummy-password"), cost)
	if err != nil {
		h, _ = bcrypt.GenerateFromPassword([]byte("xray-knife-dummy-password"), bcryptCost)
	}
	dummyHashes[cost] = h
	return h
}

// Verify checks username and password without leaking which one was wrong
// through timing: the username compare is constant-time and a bcrypt compare
// always runs, at the same cost as the real hash.
func (a *AuthDetails) Verify(username, password string) bool {
	want := sha256.Sum256([]byte(a.Username))
	got := sha256.Sum256([]byte(username))
	userOK := subtle.ConstantTimeCompare(want[:], got[:]) == 1
	hash := a.passwordHash
	if !userOK || hash == nil {
		cost, err := bcrypt.Cost(a.passwordHash)
		if err != nil {
			cost = bcryptCost
		}
		hash = dummyHashFor(cost)
	}
	passOK := bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
	return userOK && passOK && a.passwordHash != nil
}

// warmDummyHash precomputes the dummy hash so the first failed login is not
// slower than later ones.
func (a *AuthDetails) warmDummyHash() {
	cost, err := bcrypt.Cost(a.passwordHash)
	if err != nil {
		cost = bcryptCost
	}
	dummyHashFor(cost)
}

// Claims is the JWT payload.
type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// GenerateJWT makes a 24-hour JWT for the given username.
func GenerateJWT(username string) (string, error) {
	token, _, err := generateJWT(username)
	return token, err
}

func generateJWT(username string) (string, time.Time, error) {
	now := time.Now()
	expirationTime := now.Add(tokenTTL)
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", time.Time{}, err
	}
	claims := &Claims{
		Username: username,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        hex.EncodeToString(id[:]),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(jwtSecret)
	return signed, expirationTime, err
}

// ValidateJWT parses and verifies a token string, returning the claims.
// Expired tokens return an error wrapping errTokenExpired, revoked ones
// errTokenRevoked.
func ValidateJWT(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, fmt.Errorf("%w: %v", errTokenExpired, err)
		}
		return nil, err
	}
	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	// Tokens from before revocation support carry no ID; they cannot be
	// revoked, so they are refused (the user logs in again).
	if claims.ID == "" {
		return nil, fmt.Errorf("token has no id; please log in again")
	}
	if jwtUsername != "" && claims.Username != jwtUsername {
		return nil, fmt.Errorf("token issued for another user")
	}
	if revokedTokens.isRevoked(claims.ID) {
		return nil, errTokenRevoked
	}

	return claims, nil
}

// maxRevoked bounds the denylist; the entries closest to expiry go first.
const maxRevoked = 4096

// tokenDenylist holds the IDs of logged-out tokens until they would have
// expired anyway. With a path it is persisted (0600), so a logout survives
// a restart.
type tokenDenylist struct {
	mu      sync.Mutex
	revoked map[string]time.Time // jti -> expiry
	path    string
}

var revokedTokens = &tokenDenylist{revoked: make(map[string]time.Time)}

// useRevocationFile loads revocations from path (empty = memory only).
func (d *tokenDenylist) useRevocationFile(path string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.path = path
	d.revoked = make(map[string]time.Time)
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var stored map[string]time.Time
	if err := json.Unmarshal(data, &stored); err != nil {
		return fmt.Errorf("parse %s: %w", path, err)
	}
	now := time.Now()
	for id, exp := range stored {
		if exp.After(now) {
			d.revoked[id] = exp
		}
	}
	return nil
}

func (d *tokenDenylist) revoke(id string, expires time.Time) error {
	if id == "" {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	for k, exp := range d.revoked {
		if now.After(exp) {
			delete(d.revoked, k)
		}
	}
	d.revoked[id] = expires
	for len(d.revoked) > maxRevoked {
		var oldest string
		for k, exp := range d.revoked {
			if oldest == "" || exp.Before(d.revoked[oldest]) {
				oldest = k
			}
		}
		delete(d.revoked, oldest)
	}
	if d.path == "" {
		return nil
	}
	data, err := json.Marshal(d.revoked)
	if err != nil {
		return err
	}
	tmp := d.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, d.path)
}

func (d *tokenDenylist) isRevoked(id string) bool {
	if id == "" {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	_, ok := d.revoked[id]
	return ok
}

// revokeToken adds a token's ID to the denylist. Invalid tokens are ignored.
func revokeToken(tokenStr string) {
	claims := &Claims{}
	_, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}))
	if err != nil || claims.ExpiresAt == nil {
		return
	}
	_ = revokedTokens.revoke(claims.ID, claims.ExpiresAt.Time)
}

// loginLimiter throttles failed logins per client IP: a few free attempts,
// then an exponentially growing lockout. It also caps concurrent bcrypt
// work so parallel logins cannot pin every CPU.
type loginLimiter struct {
	mu         sync.Mutex
	clients    map[string]*loginAttempts
	now        func() time.Time
	freeFail   int
	baseWait   time.Duration
	maxWait    time.Duration
	slots      chan struct{}
	maxClients int // hard cap on tracked clients; the stalest is evicted
}

type loginAttempts struct {
	failures    int
	lockedUntil time.Time
	lastSeen    time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{
		clients:    make(map[string]*loginAttempts),
		now:        time.Now,
		freeFail:   5,
		baseWait:   time.Second,
		maxWait:    15 * time.Minute,
		slots:      make(chan struct{}, 4),
		maxClients: 10000,
	}
}

// allow reports whether ip may attempt a login now, and if not, how long to wait.
func (l *loginLimiter) allow(ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	a := l.clients[ip]
	if a == nil {
		return true, 0
	}
	if wait := a.lockedUntil.Sub(l.now()); wait > 0 {
		return false, wait
	}
	return true, 0
}

// acquire takes a bcrypt slot, or returns false when all are busy.
func (l *loginLimiter) acquire() bool {
	select {
	case l.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (l *loginLimiter) release() { <-l.slots }

func (l *loginLimiter) fail(ip string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.gcLocked(now)
	a := l.clients[ip]
	if a == nil {
		if len(l.clients) >= l.maxClients {
			l.evictStalestLocked()
		}
		a = &loginAttempts{}
		l.clients[ip] = a
	}
	a.failures++
	a.lastSeen = now
	if a.failures <= l.freeFail {
		return 0
	}
	exp := a.failures - l.freeFail - 1
	wait := l.maxWait
	if exp < 30 {
		if w := l.baseWait * time.Duration(math.Pow(2, float64(exp))); w < l.maxWait {
			wait = w
		}
	}
	a.lockedUntil = now.Add(wait)
	return wait
}

func (l *loginLimiter) succeed(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.clients, ip)
}

// evictStalestLocked drops the client seen longest ago, so a flood of
// source addresses cannot grow the map without bound.
func (l *loginLimiter) evictStalestLocked() {
	var stalest string
	var seen time.Time
	for ip, a := range l.clients {
		if stalest == "" || a.lastSeen.Before(seen) {
			stalest, seen = ip, a.lastSeen
		}
	}
	delete(l.clients, stalest)
}

// gcLocked forgets clients idle for longer than the maximum lockout.
func (l *loginLimiter) gcLocked(now time.Time) {
	if len(l.clients) < 1024 {
		return
	}
	for ip, a := range l.clients {
		if now.Sub(a.lastSeen) > l.maxWait && now.After(a.lockedUntil) {
			delete(l.clients, ip)
		}
	}
}

// bearerToken extracts the token from an "Authorization: Bearer <token>" header.
func bearerToken(header string) (string, bool) {
	const prefix = "bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	return strings.TrimSpace(header[len(prefix):]), true
}
