// Copyright 2024 Daniele Pintore. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

package mysqlstore

import (
	"database/sql"
	"encoding/gob"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/go-sql-driver/mysql"
	"github.com/gorilla/sessions"
)

type FlashMessage struct {
	Type    int
	Message string
}

func init() {
	gob.Register(FlashMessage{})
}
func TestMain(m *testing.M) {
	db, err := getTestingDatabase()
	if err != nil {
		log.Fatalf("DB error: %s", err.Error())
	}
	defer db.Close()
	os.Exit(m.Run())
}

func getTestingDatabase() (*sql.DB, error) {
	config := mysql.NewConfig()
	config.User = "testing"
	config.Passwd = "testing"
	config.DBName = "testing"
	config.Addr = "127.0.0.1:3306"
	config.Net = "tcp"
	config.ParseTime = true
	db, err := sql.Open("mysql", config.FormatDSN())
	if err != nil {
		return nil, err
	}
	return db, nil
}

func getMysqlStore(db *sql.DB) (*MysqlStore, error) {
	keys := []KeyPair{{AuthenticationKey: []byte("353b53ba096a0000a312c994b60de126ba9d65482a7ad4c4c451639806c26b1d"), EncryptionKey: []byte("addf66f508a5cf7b14e6f4489b2b23d2")}}
	return NewMysqlStore(db, "UserSession", keys)
}

func TestSessionsStoreOption(t *testing.T) {
	db, err := getTestingDatabase()
	if err != nil {
		t.Fatalf("TestMysqlStore: %s", err.Error())
	}
	defer db.Close()

	originalPath := "/"
	store, err := getMysqlStore(db)
	if err != nil {
		t.Fatalf("TestMysqlStore: %s", err.Error())
	}
	store.Options.Path = originalPath
	req, err := http.NewRequest("GET", "http://www.example.com", nil)
	if err != nil {
		t.Fatal("TestMysqlStore: failed to create request", err)
	}

	session, err := store.New(req, "Session")
	if err != nil {
		t.Fatalf("TestMysqlStore: failed to create session %s", err.Error())
	}

	store.Options.Path = "/foo"
	if session.Options.Path != originalPath {
		t.Fatalf("Bad session path: got %q, want %q", session.Options.Path, originalPath)
	}
}

func TestStore(t *testing.T) {
	var req *http.Request
	var rsp *httptest.ResponseRecorder
	var hdr http.Header
	var err error
	var ok bool
	var cookies []string
	var session *sessions.Session
	var flashes []interface{}
	db, err := getTestingDatabase()
	if err != nil {
		t.Fatalf("TestFlashes: %s", err.Error())
	}
	store, err := getMysqlStore(db)
	if err != nil {
		t.Fatalf("TestFlashes: %s", err.Error())
	}
	defer db.Close()
	defer store.Close()

	// Round 1 ----------------------------------------------------------------
	// Create a cookie, test some flashes and store cookie for other tests
	req, _ = http.NewRequest("GET", "http://localhost:8080/", nil)
	rsp = httptest.NewRecorder()
	// Get a session.
	if session, err = store.Get(req, "Session"); err != nil {
		t.Fatalf("Error getting session: %v", err)
	}
	// Get a flash.
	flashes = session.Flashes()
	if len(flashes) != 0 {
		t.Errorf("Expected empty flashes; Got %v", flashes)
	}
	// Add some flashes.
	session.AddFlash("foo")
	session.AddFlash("bar")
	// Custom key.
	session.AddFlash("baz", "custom_key")
	// Save.
	if err = sessions.Save(req, rsp); err != nil {
		t.Fatalf("Error saving session: %v", err)
	}
	// Save cookie for other tests
	hdr = rsp.Header()
	cookies, ok = hdr["Set-Cookie"]
	if !ok || len(cookies) != 1 {
		t.Fatal("No cookies. Header:", hdr)
	}

	// Round 2 ----------------------------------------------------------------
	// Make a request with the cookie of round 1, check flashes, set cookie to
	// delete on save (MaxAge < 0)
	req, _ = http.NewRequest("GET", "http://localhost:8080/", nil)
	req.Header.Add("Cookie", cookies[0])
	rsp = httptest.NewRecorder()
	// Get a session.
	if session, err = store.Get(req, "Session"); err != nil {
		t.Fatalf("Error getting session: %v", err)
	}
	// Check all saved values.
	flashes = session.Flashes()
	if len(flashes) != 2 {
		t.Fatalf("Expected flashes; Got %v", flashes)
	}
	if flashes[0] != "foo" || flashes[1] != "bar" {
		t.Errorf("Expected foo,bar; Got %v", flashes)
	}
	flashes = session.Flashes()
	if len(flashes) != 0 {
		t.Errorf("Expected dumped flashes; Got %v", flashes)
	}
	// Custom key flashes.
	flashes = session.Flashes("custom_key")
	if len(flashes) != 1 {
		t.Errorf("Expected flashes; Got %v", flashes)
	} else if flashes[0] != "baz" {
		t.Errorf("Expected baz; Got %v", flashes)
	}
	flashes = session.Flashes("custom_key")
	if len(flashes) != 0 {
		t.Errorf("Expected dumped flashes; Got %v", flashes)
	}

	session.Options.MaxAge = -1
	// Save.
	if err = sessions.Save(req, rsp); err != nil {
		t.Fatalf("Error saving session: %v", err)
	}

	// Round 3 ----------------------------------------------------------------
	// Store in a session a custom type, in this case is a flash but it could also
	// be stored in the Values field of the session struct
	req, _ = http.NewRequest("GET", "http://localhost:8080/", nil)
	rsp = httptest.NewRecorder()
	// Get a session.
	if session, err = store.Get(req, "Session"); err != nil {
		t.Fatalf("Error getting session: %v", err)
	}
	// Get a flash.
	flashes = session.Flashes()
	if len(flashes) != 0 {
		t.Errorf("Expected empty flashes; Got %v", flashes)
	}
	// Add some flashes.
	session.AddFlash(&FlashMessage{42, "foo"})
	// Save.
	if err = sessions.Save(req, rsp); err != nil {
		t.Fatalf("Error saving session: %v", err)
	}
	hdr = rsp.Header()
	cookies, ok = hdr["Set-Cookie"]
	if !ok || len(cookies) != 1 {
		t.Fatal("No cookies. Header:", hdr)
	}

	// Round 4 ----------------------------------------------------------------
	// Load a session that contains a custom type, and check if the data is
	// correct
	req, _ = http.NewRequest("GET", "http://localhost:8080/", nil)
	req.Header.Add("Cookie", cookies[0])
	rsp = httptest.NewRecorder()
	// Get a session.
	if session, err = store.Get(req, "Session"); err != nil {
		t.Fatalf("Error getting session: %v", err)
	}
	// Check all saved values.
	flashes = session.Flashes()
	if len(flashes) != 1 {
		t.Fatalf("Expected flashes; Got %v", flashes)
	}
	custom := flashes[0].(FlashMessage)
	if custom.Type != 42 || custom.Message != "foo" {
		t.Errorf("Expected %#v, got %#v", FlashMessage{42, "foo"}, custom)
	}

	// Save.
	if err = sessions.Save(req, rsp); err != nil {
		t.Fatalf("Error saving session: %v", err)
	}

	// Round 5 ----------------------------------------------------------------
	// Using the same cookie as round 4 delete a session via MysqlStore Delete
	// session (not exposed by gorilla sessions interface).

	req, _ = http.NewRequest("GET", "http://localhost:8080/", nil)
	req.Header.Add("Cookie", cookies[0])
	rsp = httptest.NewRecorder()
	// Get a session.
	if session, err = store.Get(req, "Session"); err != nil {
		t.Fatalf("Error getting session: %v", err)
	}

	// Delete a session
	store.Delete(req, rsp, session)
	// Get a flash.
	flashes = session.Flashes()
	if len(flashes) != 0 {
		t.Errorf("Expected empty flashes; Got %v", flashes)
	}
	if err = sessions.Save(req, rsp); err != nil {
		t.Fatalf("Error saving session: %v", err)
	}

	// Round 6 ----------------------------------------------------------------
	// Try to get the session with the same cookie (that is been deleted)
	req, _ = http.NewRequest("GET", "http://localhost:8080/", nil)
	req.Header.Add("Cookie", cookies[0])
	rsp = httptest.NewRecorder()
	// Get a session.
	_, err = store.Get(req, "Session")
	if err != nil {
		if errors.Is(err, ErrNoSessionSaved) {
			return
		}
		t.Fatalf("Error getting session: %v", err)
	}
	t.Fatal("No session should be obtained")
}
