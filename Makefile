
.DEFAULT_GOAL = build

format:
	gofumpt -l -w .

lint:
	golangci-lint run

build:
	go build -o bin/epnetmon cmd/epnetmon/*.go
