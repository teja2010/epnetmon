package ebpf_netfilter

import "fmt"

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go nf_bpf nf.c -- -O2 -g -Wall -Werror -Iinclude

type BpfObjects nf_bpfObjects

func Load() (*BpfObjects, error) {
	var obj BpfObjects
	if err := loadNf_bpfObjects(&obj, nil); err != nil {
		return nil, fmt.Errorf("Error loading bpf objects: %w", err)
	}

	return &obj
}

func (bo *BpfObjects) Hook(hook, priority uint32) error {
}
