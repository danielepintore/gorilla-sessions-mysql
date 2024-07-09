package mysqlstore

import (
	"database/sql"
	"encoding/gob"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

type MysqlStore struct {
	db         *sql.DB
	tableName  string
	stmtSelect *sql.Stmt
	stmtInsert *sql.Stmt
	stmtUpdate *sql.Stmt
	stmtDelete *sql.Stmt

	Codecs  []securecookie.Codec
	Options *sessions.Options // default configuration
}

type KeyPair struct {
	AuthenticationKey []byte
	EncryptionKey     []byte
}

type MysqlStoreOption func(*MysqlStore)

type sessionTableStructure struct {
	id          int
	sessionData string
	createdAt   time.Time
	modifiedAt  time.Time
	expiresAt   time.Time
}

func init() {
	gob.Register(time.Time{})
}

// TODO: in docs remember to advise that parseTime should be enabled
// Create a new store from a database connection, in order to work correctly
// you need to ensure that the db connection has the parseTime flag set to true
func NewMysqlStore(db *sql.DB, tableName string, keys []KeyPair, opts ...MysqlStoreOption) (*MysqlStore, error) {
	if db == nil {
		return nil, errors.New("Cannot instantiate the store: db is nil")
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("Cannot instantiate the store: %s", err.Error())
	}

	store := &MysqlStore{
		db:        db,
		tableName: tableName,

		Codecs: securecookie.CodecsFromPairs(parseKeyPairs(keys)...),
		Options: &sessions.Options{
			Path:     "/",
			MaxAge:   3600,
			SameSite: http.SameSiteNoneMode,
			Secure:   true,
			HttpOnly: true,
		},
	}

	// Apply store options
	for _, opt := range opts {
		opt(store)
	}

	if err := store.createSessionTable(); err != nil {
		return nil, fmt.Errorf("Cannot instantiate the store: %s", err.Error())
	}

	if err := store.prepareQueryStatements(); err != nil {
		return nil, fmt.Errorf("Cannot instantiate the store: %s", err.Error())
	}

	return store, nil
}

// Creates a new store using a dns string in order to create the database connection
// It is important that the dsn string has the option parseTime=true in order to
// enable the driver to convert the colums TIMESTAMP and DATETIME in time.Time
func NewMysqlStoreFromDsn(dsn string, tableName string, keys []KeyPair, opts ...MysqlStoreOption) (*MysqlStore, error) {
	if !strings.Contains(dsn, "parseTime=true") {
		return nil, errors.New("Cannot instantiate the store: parseTime needs to be true")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("Cannot instantiate the store: %s", err.Error())
	}
	return NewMysqlStore(db, tableName, keys, opts...)
}

func (store *MysqlStore) Close() {
	store.db.Close()
	if store.stmtSelect != nil {store.stmtSelect.Close()}
	store.stmtUpdate.Close()
	store.stmtDelete.Close()
	store.stmtInsert.Close()
}

// Sets the path of the cookie
func WithPath(path string) MysqlStoreOption {
	return func(store *MysqlStore) {
		store.Options.Path = path
	}
}

// Sets httpOnly attribute of the cookie
func WithHttpOnly(httpOnly bool) MysqlStoreOption {
	return func(store *MysqlStore) {
		store.Options.HttpOnly = httpOnly
	}
}

// Sets SameSite attribute of the cookie
func WithSameSite(sameSite http.SameSite) MysqlStoreOption {
	return func(store *MysqlStore) {
		store.Options.SameSite = sameSite
	}
}

// Sets the maxAge of the cookie
// MaxAge=0 means no Max-Age attribute specified and the cookie will be
// deleted after the browser session ends.
// MaxAge<0 means delete cookie immediately.
// MaxAge>0 means Max-Age attribute present and given in seconds.
func WithMaxAge(maxAge int) MysqlStoreOption {
	return func(store *MysqlStore) {
		store.Options.MaxAge = maxAge
	}
}

// Sets the domain of the cookie
func WithDomain(domain string) MysqlStoreOption {
	return func(store *MysqlStore) {
		store.Options.Domain = domain
	}
}

// Sets the secure boolean to the cookie
func WithSecure(secure bool) MysqlStoreOption {
	return func(store *MysqlStore) {
		store.Options.Secure = secure
	}
}

func parseKeyPairs(keys []KeyPair) [][]byte {
	var keyList [][]byte
	for _, key := range keys {
		keyList = append(keyList, key.AuthenticationKey, key.EncryptionKey)
	}
	return keyList
}

func (store *MysqlStore) prepareQueryStatements() error {
	var err error
	selectQuery := "SELECT id, sessionData, createdAt, modifiedAt, expiresAt FROM " +
		store.tableName + " WHERE id = ?"
	store.stmtSelect, err = store.db.Prepare(selectQuery)
	if err != nil {
		return err
	}

	insertQuery := "INSERT INTO " + store.tableName +
		"(id, sessionData, createdAt, modifiedAt, expiresAt) VALUES (NULL, ?, ?, ?, ?)"
	store.stmtInsert, err = store.db.Prepare(insertQuery)
	if err != nil {
		return err
	}

	deleteQuery := "DELETE FROM " + store.tableName + " WHERE id = ?"
	store.stmtDelete, err = store.db.Prepare(deleteQuery)
	if err != nil {
		return err
	}

	updateQuery := "UPDATE " + store.tableName +
		" SET sessionData = ?, createdAt = ?, expiresAt = ? WHERE id = ?"
	store.stmtUpdate, err = store.db.Prepare(updateQuery)
	if err != nil {
		return err
	}

	return nil
}

func (store *MysqlStore)createSessionTable() error {
	createTableSql := `
		CREATE TABLE IF NOT EXISTS ` + "`" + store.tableName + "`" + ` (
			id int(11) NOT NULL AUTO_INCREMENT,
  		sessionData mediumblob DEFAULT NULL,
  		createdAt timestamp NOT NULL DEFAULT current_timestamp(),
  		modifiedAt timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  		expiresAt timestamp NOT NULL DEFAULT current_timestamp(),
			PRIMARY KEY (` + "`id`" + `)
		);
	`
	if _, err := store.db.Exec(createTableSql); err != nil {
		return fmt.Errorf("Cannot instantiate the store: %s", err.Error())
	}
	return nil
}

// Get should return a cached session.
// Get returns a session for the given name after adding it to the registry.
//
// It returns a new session if the sessions doesn't exist. Access IsNew on
// the session to check if it is an existing session or a new one.
//
// It returns a new session and an error if the session exists but could
// not be decoded.
func (store *MysqlStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(store, name)
}

// New should create and return a new session.
//
// Note that New should never return a nil session, even in the case of
// an error if using the Registry infrastructure to cache the session.
// New returns a session for the given name without adding it to the registry.
//
// The difference between New() and Get() is that calling New() twice will
// decode the session data twice, while Get() registers and reuses the same
// decoded session after the first cal
func (store *MysqlStore) New(r *http.Request, name string) (*sessions.Session, error) {
	session := sessions.NewSession(store, name)
	opts := *store.Options
	session.Options = &opts
	session.IsNew = true
	var err error
	if c, errCookie := r.Cookie(name); errCookie == nil {
		err = securecookie.DecodeMulti(name, c.Value, &session.ID, store.Codecs...)
		if err == nil {
			err = store.load(session)
			if err == nil {
				session.IsNew = false
			}
		}
	}
	return session, err
}

// Save should persist session to the underlying store implementation.
func (store *MysqlStore) Save(r *http.Request, w http.ResponseWriter, s *sessions.Session) error {
	// Delete if max-age is <= 0
	if s.Options.MaxAge <= 0 {
		if err := store.delete(s); err != nil {
			return err
		}
		http.SetCookie(w, sessions.NewCookie(s.Name(), "", s.Options))
		return nil
	}

	if s.ID == "" {
		if err := store.insert(s); err != nil {
			return err
		}
	} else if err := store.update(s); err != nil {
		return err
	}
	encoded, err := securecookie.EncodeMulti(s.Name(), s.ID,
		store.Codecs...)
	if err != nil {
		return err
	}
	http.SetCookie(w, sessions.NewCookie(s.Name(), encoded, s.Options))
	return nil
}

func (store *MysqlStore) Delete(r *http.Request, w http.ResponseWriter, session *sessions.Session) {
	// Set cookie to expire.
	options := session.Options
	options.MaxAge = -1

	// Clear session values.
	for k := range session.Values {
		delete(session.Values, k)
	}

}

func (store *MysqlStore) delete(session *sessions.Session) error {
	_, err := store.stmtDelete.Exec(session.ID)
	if err != nil {
		return err
	}
	return nil
}

// Runs when we add a new session in the store
func (store *MysqlStore) insert(session *sessions.Session) error {
	var createdAt, modifiedAt, expiresAt time.Time
	sessionCreatedAt := session.Values["createdAt"]
	if sessionCreatedAt == nil {
		createdAt = time.Now()
	} else {
		createdAt = sessionCreatedAt.(time.Time)
	}
	modifiedAt = createdAt
	sessionExipresAt := session.Values["expiresAt"]
	if sessionExipresAt == nil {
		expiresAt = time.Now().Add(time.Second * time.Duration(session.Options.MaxAge))
	} else {
		expiresAt = sessionExipresAt.(time.Time)
	}
	delete(session.Values, "createdAt")
	delete(session.Values, "expiresAt")
	delete(session.Values, "modifiedAt")

	encoded, err := securecookie.EncodeMulti(session.Name(), session.Values, store.Codecs...)
	if err != nil {
		return err
	}
	res, err := store.stmtInsert.Exec(encoded, createdAt, modifiedAt, expiresAt)
	if err != nil {
		return err
	}
	lastInsertedId, err := res.LastInsertId()
	if err != nil {
		return err
	}
	session.ID = fmt.Sprintf("%d", lastInsertedId)
	return nil
}

func (store *MysqlStore) update(session *sessions.Session) error {
	if session.IsNew == true {
		return store.insert(session)
	}
	var createdAt, expiresAt time.Time
	sessionCreatedAt := session.Values["createdAt"]
	if sessionCreatedAt == nil {
		createdAt = time.Now()
	} else {
		createdAt = sessionCreatedAt.(time.Time)
	}

	sessionExpireAt := session.Values["expiresAt"]
	if sessionExpireAt == nil {
		expiresAt = time.Now().Add(time.Second * time.Duration(session.Options.MaxAge))
	} else {
		expiresAt = sessionExpireAt.(time.Time)
		if expiresAt.Sub(time.Now().Add(time.Second*time.Duration(session.Options.MaxAge))) < 0 { // If session is not expired
			// Refresh expiresAt
			expiresAt = time.Now().Add(time.Second * time.Duration(session.Options.MaxAge))
		}
	}

	// Delete this fields since are stored on the table
	delete(session.Values, "createdAt")
	delete(session.Values, "expiresAt")
	delete(session.Values, "modifiedAt")
	encoded, err := securecookie.EncodeMulti(session.Name(), session.Values, store.Codecs...)
	if err != nil {
		return err
	}
	_, err = store.stmtUpdate.Exec(encoded, createdAt, expiresAt, session.ID)
	if err != nil {
		return err
	}
	return nil
}

// load makes a query to the db to load the sessions data from the database
func (store *MysqlStore) load(session *sessions.Session) error {
	row := store.stmtSelect.QueryRow(session.ID)
	sess := sessionTableStructure{}
	err := row.Scan(&sess.id, &sess.sessionData, &sess.createdAt, &sess.modifiedAt, &sess.expiresAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("MysqlStore: Session with Id: %s not found", session.ID)
		}
		return err
	}
	if sess.expiresAt.Sub(time.Now()) < 0 {
		return errors.New("MysqlStore: Session expired!")
	}
	err = securecookie.DecodeMulti(session.Name(), sess.sessionData, &session.Values, store.Codecs...)
	if err != nil {
		return err
	}
	session.Values["createdAt"] = sess.createdAt
	session.Values["modifiedAt"] = sess.modifiedAt
	session.Values["expiresAt"] = sess.expiresAt
	return nil
}
