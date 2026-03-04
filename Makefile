BINARY_NAME := fgp
BUILD_DIR := build
IMAGE_NAME := unicity-fgp:local

all: clean test build

clean:
	rm -rf $(BUILD_DIR)

test:
	go test ./... -count=1

build:
	mkdir -p $(BUILD_DIR)
	CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd

build-docker:
	docker build -t $(IMAGE_NAME) -f Dockerfile .