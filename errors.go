package mysqlstore

import (
	"errors"
	"fmt"
)

// Error definitions
var (
	ErrAddingSessionTable            = errors.New("There was an error while trying to add the session table to the database.")
	ErrDbConnectionIsNil             = errors.New("The connection struct is nil!")
	ErrDbOpenConnection              = errors.New("There was an error while opening the database connection!")
	ErrDbPing                        = errors.New("There was an error while pinging the database!")
	ErrFailedToDecodeCookie          = errors.New("Failed to decode the cookie.")
	ErrFailedToDecodeSessionData     = errors.New("Failed to decode session data from the database.")
	ErrFailedToDeleteExpiredSessions = errors.New("There was an error while trying to delete expired users sessions.")
	ErrFailedToDeleteSession         = errors.New("Failed to delete a session.")
	ErrFailedToEncodeCookie          = errors.New("Failed to encode the cookie.")
	ErrFailedToEncodeSessionData     = errors.New("Failed to encode session data.")
	ErrFailedToInsertSession         = errors.New("Failed to insert a session in the database.")
	ErrFailedToLoadSession           = errors.New("Failed to load session.")
	ErrFailedToPrepareStmt           = errors.New("There was an error while trying to parse the sql prepared statement.")
	ErrFailedToUpdateSession         = errors.New("Failed to update a sessionData in the database.")
	ErrLoadingSessionDataFromDb      = errors.New("Failed to load session data from the database.")
	ErrNoParseTimeParameter          = errors.New("You need the parseTime=true parameter in the DSN string.")
	ErrNoSessionSaved                = errors.New("There isn't a sessions for that Id in the database.")
	ErrSessionExpired                = errors.New("The session is expired.")
)

type MySqlStoreError struct {
	funcName string
	err      error
}

// Implement the Error interface
func (e MySqlStoreError) Error() string {
	return fmt.Sprintf("%s: %s", e.funcName, e.err.Error())
}

// Implement the Unwrap interface
func (e MySqlStoreError) Unwrap() error {
	return e.err
}

func NewMysqlStoreError(funcName string, err error) error {
	return MySqlStoreError{funcName: funcName, err: err}
}

func FromError(funcName string, err error) error {
	return MySqlStoreError{funcName: funcName, err: err}
}
