package ebpf_netfilter

import (
	"fmt"

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go nf_bpf nf.c -- -O2 -g -Wall -Werror -Iinclude

type BpfObjects nf_bpfObjects

func Load() (*BpfObjects, error) {
	var obj BpfObjects
	if err := loadNf_bpfObjects(&obj, nil); err != nil {
		return nil, fmt.Errorf("Error loading bpf objects: %w", err)
	}

	return &obj, nil
}

type Hook uint32

const ( // possible values of hook
	HOOK_PRE_ROUTING  Hook = unix.NF_INET_PRE_ROUTING
	HOOK_LOCAL_IN     Hook = unix.NF_INET_LOCAL_IN
	HOOK_FORWARD      Hook = unix.NF_INET_FORWARD
	HOOK_LOCAL_OUT    Hook = unix.NF_INET_LOCAL_OUT
	HOOK_POST_ROUTING Hook = unix.NF_INET_POST_ROUTING
)

type Priority int32

const ( // some well known priorities that can be used in all hooks
	PRIORITY_RAW      Priority = -300
	PRIORITY_mangle   Priority = -150
	PRIORITY_FILTER   Priority = 0
	PRIORITY_security Priority = 50
)

type ProtocolFamily uint32

const (
	PROTOCOL_FAMILY_IPV4 ProtocolFamily = unix.NFPROTO_IPV4
	PROTOCOL_FAMILY_IPV6 ProtocolFamily = unix.NFPROTO_IPV6
)

func (bo *BpfObjects) Attach(pf ProtocolFamily, hook Hook, priority Priority) (link.Link, error) {
	l, err := link.AttachNetfilter(link.NetfilterOptions{
		Program:        bo.NfCount,
		ProtocolFamily: uint32(pf),
		HookNumber:     uint32(hook),
		Priority:       int32(priority),
		Flags:          0,
		NetfilterFlags: link.NetfilterIPDefrag,
	})
	if err != nil {
		return nil, fmt.Errorf("Error Attaching netfilter ebpf prog: %w", err)
	}
	return l, nil
}
