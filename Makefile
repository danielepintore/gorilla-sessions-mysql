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

docs:
	-clean
	godoc -http=:6060

copyright:
	python3 scripts/check_copyright.py

update-pkg-cache:
	-mkdir tmp_update_pkg;
	cd tmp_update_pkg; go mod init test; GOPROXY=https://proxy.golang.org GO111MODULE=on go get github.com/$(USER)/$(PACKAGE)@v$(VERSION);
	-rm -rf tmp_update_pkg;
