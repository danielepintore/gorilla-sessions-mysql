// Copyright 2024 Daniele Pintore. All rights reserved.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.

// Package mysqlstore provides a store implementation for gorilla/sessions that
// store data in a mysql database
//
// # Installation
//
// You can install this package by running: 
//	go get github.com/danielepintore/gorilla-sessions-mysql
//
// # Usage
//
// To get a store you just need a [sql.DB] struct or a dsn string, you need to
// specify the TableName, that is the name of the table where your sessions will
// be saved in the database. You can put even a TableName that doesn't exist, the
// table will be created. Then you need to pass a list of [KeyPair], the requirements
// for a [KeyPair] are the one specified by the gorilla/sessions package.
//
//	// This provides a store with the default settings for a session
//	// For more customization look futher examples
//	mysqlStore, err := mysqlstore.NewMysqlStore(db, "TableName",
//		[]mysqlstore.KeyPair{{AuthenticationKey: []byte(os.Getenv("SESSION_AUTH_KEY")), EncryptionKey: []byte(os.Getenv("SESSION_ENC_KEY"))}}
//	)
//	if err != nil {
//		panic(fmt.Sprintf("Failed to get a mysqlstore: %s", err.Error()))
//	}
// Then you can use the store in a handle like this:
//	func myHandler(w http.ResponseWriter, r *http.Request) {
//		session, err := mysqlStore.Get(r, "CookieName") // Get a session
//		if err != nil {
//			if !(errors.Is(err, mysqlstore.ErrSessionExpired) || errors.Is(err, mysqlstore.ErrNoSessionSaved)) {
//				// Handle errors here, remember that the Get() method will always return a session, even when
//				// there is a error, for example here we get in this if we'll have a new session
//				return
//			}
//		}
//		// do things with the session data
//		// Save it before we write to the response/return from the handler.
//		err := mysqlStore.Save(r, w)
//		if err != nil {
//			http.Error(w, err.Error(), http.StatusInternalServerError)
//			return
//		}
//	}
// This package provides also a cleanup option to delete expired sessions from the database,
// to use this feature, while creating the store just pass the [MysqlStoreOption] WithCleanupInterval():
//	mysqlStore, err := mysqlstore.NewMysqlStore(db, "TableName",
//		[]mysqlstore.KeyPair{{AuthenticationKey: []byte(os.Getenv("SESSION_AUTH_KEY")), EncryptionKey: []byte(os.Getenv("SESSION_ENC_KEY"))}},
//		WithCleanupInterval(time.Minute * 15)
//	)
// Now every 15 minutes the package will perform a check and will delete all expired sessions.
// There are other MysqlStoreOption, refer to the documentation to see how they change the behavior of the store.
package mysqlstore
