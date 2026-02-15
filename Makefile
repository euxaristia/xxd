# xxd Makefile

BINARY_NAME=xxd
MODULE=github.com/euxaristia/xxd

all: build

build:
	go build -o $(BINARY_NAME) $(MODULE)/cmd/xxd

install: build
	cp $(BINARY_NAME) /usr/local/bin/

clean:
	rm -f $(BINARY_NAME)
	rm -f xxd-go

test:
	go test ./...

.PHONY: all build install clean test
