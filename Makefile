.PHONY: build run test clean docker lint

BINARY_NAME=coldforge-signer
DOCKER_IMAGE=coldforge-signer

build:
	go build -o bin/$(BINARY_NAME) ./cmd/signer

run: build
	./bin/$(BINARY_NAME)

test:
	go test -v ./...

test-coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

clean:
	rm -rf bin/
	rm -f coverage.out coverage.html

docker:
	docker build -t $(DOCKER_IMAGE):latest .

docker-run: docker
	docker run -p 7777:7777 $(DOCKER_IMAGE):latest

lint:
	golangci-lint run

fmt:
	go fmt ./...

tidy:
	go mod tidy

dev:
	go run ./cmd/signer
