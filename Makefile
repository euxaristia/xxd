# xxd Makefile

BINARY_NAME=xxd
MODULE=github.com/euxaristia/xxd

all: build

build:
	go build -o $(BINARY_NAME) $(MODULE)/cmd/xxd

install: build
	mkdir -p $(HOME)/.local/bin
	cp $(BINARY_NAME) $(HOME)/.local/bin/

clean:
	rm -f $(BINARY_NAME)
	rm -f xxd-go

test:
	go test ./...

.PHONY: all build install clean test
