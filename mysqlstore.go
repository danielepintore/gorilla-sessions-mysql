// Copyright 2024 Daniele Pintore. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

package mysqlstore

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

// MysqlStore provides session data from a mysql database
type MysqlStore struct {
	db         *sql.DB
	tableName  string
	stmtSelect *sql.Stmt
	stmtInsert *sql.Stmt
	stmtUpdate *sql.Stmt
	stmtDelete *sql.Stmt

	shouldCleanup   bool
	cleanupInterval time.Duration
	stopCleanup     chan struct{}
	cleanupDone     chan struct{}
	cleanupErr      chan error

	Codecs  []securecookie.Codec
	Options *sessions.Options // default configuration
}

// A [KeyPair] rappresent two keys, an AuthenticationKey used for signing and a
// optional (can be nil) EncryptionKey for encryption
type KeyPair struct {
	AuthenticationKey []byte
	EncryptionKey     []byte
}

// A list of MysqlStoreOption can be used when creating a MysqlStore when using
// [NewMysqlStore] or [NewMysqlStoreFromDsn]
type MysqlStoreOption func(*MysqlStore)

// sessionTableStructure rappresent the structure of the table used in the
// database to store sessions
type sessionTableStructure struct {
	id          int
	sessionData string
	createdAt   time.Time
	modifiedAt  time.Time
	expiresAt   time.Time
}

// NewMysqlStore creates a new [MysqlStore] that can be used to retrieve and save
// user sessions from a database.
// IMPORTANT: When passing the database connection make sure to have the option
// parseTime set to true, otherwise you may have problems.
func NewMysqlStore(db *sql.DB, tableName string, keys []KeyPair, opts ...MysqlStoreOption) (*MysqlStore, error) {
	if db == nil {
		return nil, fromError("NewMysqlStore", ErrDbConnectionIsNil)
	}
	if err := db.Ping(); err != nil {
		return nil, fromError("NewMysqlStore", errors.Join(ErrDbPing, err))
	}

	store := &MysqlStore{
		db:              db,
		tableName:       tableName,
		shouldCleanup:   false,
		cleanupInterval: 0,

		Codecs: securecookie.CodecsFromPairs(parseKeyPairs(keys)...),
		Options: &sessions.Options{
			Path:     "/",
			MaxAge:   3600,
			SameSite: http.SameSiteNoneMode,
			Secure:   true,
			HttpOnly: true,
		},
	}

	// set maxAge for the codecs
	store.SetMaxAge(store.Options.MaxAge)

	// Apply store options
	for _, opt := range opts {
		opt(store)
	}

	if err := store.createSessionTable(); err != nil {
		return nil, fromError("NewMysqlStore", errors.Join(ErrAddingSessionTable, err))
	}

	if err := store.prepareQueryStatements(); err != nil {
		return nil, fromError("NewMysqlStore", errors.Join(ErrFailedToPrepareStmt, err))
	}

	// Start cleanup goroutine if shouldCleanup is true
	if store.shouldCleanup {
		store.stopCleanup, store.cleanupDone, store.cleanupErr = make(chan struct{}), make(chan struct{}), make(chan error)
		go store.cleanup(store.stopCleanup, store.cleanupDone, store.cleanupErr)
	}

	return store, nil
}

// NewMysqlStoreFromDsn creates a new [MysqlStore] that can be used to retrieve and save
// user sessions from a database, it uses a dsn string to create a connection to
// the database.
// IMPORTANT: The dsn string should contain the parameter parseTime=true
// otherwise you may have problems.
func NewMysqlStoreFromDsn(dsn string, tableName string, keys []KeyPair, opts ...MysqlStoreOption) (*MysqlStore, error) {
	if !strings.Contains(dsn, "parseTime=true") {
		return nil, fromError("NewMysqlStoreFromDsn", ErrNoParseTimeParameter)
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fromError("NewMysqlStoreFromDsn", errors.Join(ErrDbOpenConnection, err))
	}
	return NewMysqlStore(db, tableName, keys, opts...)
}

// Close stop the cleanup goroutine and closes the database connection
func (store *MysqlStore) Close() {
	if store.shouldCleanup {
		store.stopSessionsCleanup(store.stopCleanup, store.cleanupDone)
	}
	store.stmtSelect.Close()
	store.stmtUpdate.Close()
	store.stmtDelete.Close()
	store.stmtInsert.Close()
	store.db.Close()
}

// WithPath returns a [MysqlStoreOption] that allows to change the path parameter
// of the session cookie that is provided by default when creating a new session
func WithPath(path string) MysqlStoreOption {
	return func(store *MysqlStore) {
		store.Options.Path = path
	}
}

// WithHttpOnly returns a [MysqlStoreOption] that allows to change the httpOnly parameter
// of the session cookie that is provided by default when creating a new session
func WithHttpOnly(httpOnly bool) MysqlStoreOption {
	return func(store *MysqlStore) {
		store.Options.HttpOnly = httpOnly
	}
}

// WithSameSite returns a [MysqlStoreOption] that allows to change the sameSite parameter
// of the session cookie that is provided by default when creating a new session
func WithSameSite(sameSite http.SameSite) MysqlStoreOption {
	return func(store *MysqlStore) {
		store.Options.SameSite = sameSite
	}
}

// WithMaxAge returns a [MysqlStoreOption] that allows to change the maxAge parameter
// of the session cookie that is provided by default when creating a new session
// MaxAge=0 means no Max-Age attribute specified and the cookie will be
// deleted after the browser session ends.
// MaxAge<0 means delete cookie immediately.
// MaxAge>0 means Max-Age attribute present and given in seconds.
func WithMaxAge(maxAge int) MysqlStoreOption {
	return func(store *MysqlStore) {
		store.SetMaxAge(maxAge)
	}
}

// SetMaxAge sets the maxAge parameter for the cookie
func (store *MysqlStore)SetMaxAge(maxAge int) {
		store.Options.MaxAge = maxAge

		// Set the maxAge for each securecookie instance.
		for _, codec := range store.Codecs {
			if sc, ok := codec.(*securecookie.SecureCookie); ok {
				sc.MaxAge(maxAge)
			}
		}
}

// WithDomain returns a [MysqlStoreOption] that allows to change the domain parameter
// of the session cookie that is provided by default when creating a new session
func WithDomain(domain string) MysqlStoreOption {
	return func(store *MysqlStore) {
		store.Options.Domain = domain
	}
}

// WithSecure returns a [MysqlStoreOption] that allows to change the secure parameter
// of the session cookie that is provided by default when creating a new session
func WithSecure(secure bool) MysqlStoreOption {
	return func(store *MysqlStore) {
		store.Options.Secure = secure
	}
}

// WithCleanupInterval returns a [MysqlStoreOption] that allows to enable and
// set the cleanup interval, the cleanup interval is the time between each
// scan to remove exipired sessions from the database
func WithCleanupInterval(interval time.Duration) MysqlStoreOption {
	return func(store *MysqlStore) {
		store.shouldCleanup = true
		store.cleanupInterval = interval
	}
}

// parseKeyPairs is a helper function used to parse the []KeyPair to a [][]byte
// that we need to instantiate the Codec
func parseKeyPairs(keys []KeyPair) [][]byte {
	var keyList [][]byte
	for _, key := range keys {
		keyList = append(keyList, key.AuthenticationKey, key.EncryptionKey)
	}
	return keyList
}

// prepareQueryStatements prepares the stmt statements that will be used while
// using the store
func (store *MysqlStore) prepareQueryStatements() error {
	var err error
	selectQuery := "SELECT id, sessionData, createdAt, modifiedAt, expiresAt FROM " +
		store.tableName + " WHERE id = ?"
	store.stmtSelect, err = store.db.Prepare(selectQuery)
	if err != nil {
		return fromError("prepareQueryStatements->SELECT", err)
	}

	insertQuery := "INSERT INTO " + store.tableName +
		"(id, sessionData, createdAt, modifiedAt, expiresAt) VALUES (NULL, ?, ?, ?, ?)"
	store.stmtInsert, err = store.db.Prepare(insertQuery)
	if err != nil {
		return fromError("prepareQueryStatements->INSERT", err)
	}

	deleteQuery := "DELETE FROM " + store.tableName + " WHERE id = ?"
	store.stmtDelete, err = store.db.Prepare(deleteQuery)
	if err != nil {
		return fromError("prepareQueryStatements->DELETE", err)
	}

	updateQuery := "UPDATE " + store.tableName +
		" SET sessionData = ?, createdAt = ?, expiresAt = ? WHERE id = ?"
	store.stmtUpdate, err = store.db.Prepare(updateQuery)
	if err != nil {
		return fromError("prepareQueryStatements->UPDATE", err)
	}

	return nil
}

// createSessionTable is a helper function used to create the session table
// (the table where all session data is stored in the database) if it doesn't
// exist
func (store *MysqlStore) createSessionTable() error {
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
		return fromError("createSessionTable", err)
	}
	return nil
}

// stopSessionsCleanup is a helper function that allows to stop the cleanup
// goroutine
func (store *MysqlStore) stopSessionsCleanup(stopCleanup chan<- struct{}, cleanupDone <-chan struct{}) {
	stopCleanup <- struct{}{}
	<-cleanupDone
	store.shouldCleanup = false
}

// cleanup is the goroutine used to remove expired sessions from the database
// The first channel only sends data while the second one only receive data
func (store *MysqlStore) cleanup(stopCleanup <-chan struct{}, cleanupDone chan<- struct{}, error chan<- error) {
	ticker := time.NewTicker(store.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-stopCleanup:
			// Handle the quit signal.
			cleanupDone <- struct{}{}
			return
		case <-ticker.C:
			// Delete expired sessions on each tick.
			if err := store.deleteExpiredSessions(); err != nil {
				error <- fromError("MysqlStore.cleanup", errors.Join(ErrFailedToDeleteExpiredSessions, err))
			}
		}
	}
}

// deleteExpiredSessions is a helper function used to delete all expired sessions
// from the database
func (store *MysqlStore) deleteExpiredSessions() error {
	deleteQuery := "DELETE FROM " + store.tableName + " WHERE expiresAt < NOW()"
	if _, err := store.db.Exec(deleteQuery); err != nil {
		return err
	}
	return nil
}

// ----------------------------------------------------------------------------
// ----------------- Implementation of the Store interface --------------------
// ----------------------------------------------------------------------------

// Get should return a cached session.
// Get returns a session for the given name after adding it to the registry.
//
// It returns a new session if the sessions doesn't exist. Access IsNew on
// the session to check if it is an existing session or a new one.
//
// It returns a new session and an error if the session exists but could
// not be decoded or is expired.
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
// decoded session after the first call
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
			} else if errors.Is(err, sql.ErrNoRows) {
				err = fromError("MysqlStore.New", errors.Join(ErrNoSessionSaved, err))
			} else {
				err = fromError("MysqlStore.New", errors.Join(ErrLoadingSessionDataFromDb, err))
			}
		} else {
			err = fromError("MysqlStore.New", errors.Join(ErrFailedToDecodeCookie, err))
		}
	}
	return session, err
}

// Save stores the session data in the database
func (store *MysqlStore) Save(r *http.Request, w http.ResponseWriter, s *sessions.Session) error {
	// Delete if max-age is <= 0
	if s.Options.MaxAge <= 0 {
		if err := store.delete(s); err != nil {
			return fromError("MysqlStore.Save", errors.Join(ErrFailedToDeleteSession, err))
		}
		http.SetCookie(w, sessions.NewCookie(s.Name(), "", s.Options))
		return nil
	}

	if s.ID == "" {
		if err := store.insert(s); err != nil {
			return fromError("MysqlStore.Save", errors.Join(ErrFailedToInsertSession, err))
		}
	} else if err := store.update(s); err != nil {
		return fromError("MysqlStore.Save", errors.Join(ErrFailedToUpdateSession, err))
	}
	encoded, err := securecookie.EncodeMulti(s.Name(), s.ID,
		store.Codecs...)
	if err != nil {
		return fromError("MysqlStore.Save", errors.Join(ErrFailedToDecodeCookie, err))
	}
	http.SetCookie(w, sessions.NewCookie(s.Name(), encoded, s.Options))
	return nil
}

// Delete change the session options in order that it will be deleted when calling
// [Save]
func (store *MysqlStore) Delete(r *http.Request, w http.ResponseWriter, session *sessions.Session) {
	// Set cookie to expire.
	options := session.Options
	options.MaxAge = -1

	// Clear session values.
	for k := range session.Values {
		delete(session.Values, k)
	}
}

// load is a helper function that makes a query to the database to load the data
// of a session identified by the session.ID
func (store *MysqlStore) load(session *sessions.Session) error {
	row := store.stmtSelect.QueryRow(session.ID)
	sess := sessionTableStructure{}
	err := row.Scan(&sess.id, &sess.sessionData, &sess.createdAt, &sess.modifiedAt, &sess.expiresAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return fromError("MysqlStore.load", errors.Join(ErrNoSessionSaved, err))
		}
		return fromError("MysqlStore.load", errors.Join(ErrFailedToLoadSession, err))
	}
	if sess.expiresAt.Sub(time.Now()) < 0 {
		return fromError("MysqlStore.load", ErrSessionExpired)
	}
	err = securecookie.DecodeMulti(session.Name(), sess.sessionData, &session.Values, store.Codecs...)
	if err != nil {
		return fromError("MysqlStore.load", errors.Join(ErrFailedToDecodeSessionData, err))
	}
	session.Values["createdAt"] = sess.createdAt
	session.Values["modifiedAt"] = sess.modifiedAt
	session.Values["expiresAt"] = sess.expiresAt
	return nil
}

// insert is a helper function that is used to add new sessions to the database
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
		return fromError("MysqlStore.insert", errors.Join(ErrFailedToEncodeSessionData, err))
	}
	res, err := store.stmtInsert.Exec(encoded, createdAt, modifiedAt, expiresAt)
	if err != nil {
		return fromError("MysqlStore.insert", errors.Join(ErrFailedToInsertSession, err))
	}
	lastInsertedId, err := res.LastInsertId()
	if err != nil {
		return fromError("MysqlStore.insert", errors.Join(ErrFailedToInsertSession, err))
	}
	session.ID = fmt.Sprintf("%d", lastInsertedId)
	return nil
}

// update is a helper function used to store the updated session values in the
// database
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
		return fromError("MysqlStore.update", errors.Join(ErrFailedToEncodeSessionData, err))
	}
	_, err = store.stmtUpdate.Exec(encoded, createdAt, expiresAt, session.ID)
	if err != nil {
		return fromError("MysqlStore.update", errors.Join(ErrFailedToUpdateSession, err))
	}
	return nil
}

// delete is a helper function used to delete a session identified by the
// session.ID from the database
func (store *MysqlStore) delete(session *sessions.Session) error {
	_, err := store.stmtDelete.Exec(session.ID)
	if err != nil {
		return err
	}
	return nil
}
