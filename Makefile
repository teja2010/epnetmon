export BPF2GO_CC := clang-18
export BPF2GO_STRIP := llvm-strip-18

.DEFAULT_GOAL = build

.PHONY: format
format:
	gofumpt -l -w .
	clang-format-18 -i internal/c_include/bpf_kfuncs.h internal/ebpf_netfilter/nf.c 

.PHONY: lint
lint:
	golangci-lint run

generate:
	go generate ./internal/ebpf_netfilter

generate_vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > internal/c_include/vmlinux.h

.PHONY: build
build:
	go build -o bin/epnetmon cmd/epnetmon/*.go

.PHONY: test
test:
	go test -v ./...
