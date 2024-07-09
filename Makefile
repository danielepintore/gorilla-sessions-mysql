TEST_BINARY=./dist/test/mysqlstore

clean:
	go clean
	-rm ${TEST_BINARY}

tests:
	-clean
	go test ./... -p 1 -c -o ${TEST_BINARY}
	${TEST_BINARY} 2> /dev/null

tests-verbose:
	-clean
	go test ./... -p 1 -c -o ${TEST_BINARY}
	${TEST_BINARY}
