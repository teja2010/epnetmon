// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64

package ebpf_netfilter

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type nf_bpfFlowStatsT struct {
	Pid   uint64
	Comm  [16]uint8
	Bytes uint64
	Pkts  uint64
}

type nf_bpfFlowT struct {
	Protocol  uint16
	Hole      [2]uint8
	Ipv4Saddr uint32
	Ipv4Daddr uint32
	Dport     uint16
	Sport     uint16
}

type nf_bpfMetricsT struct {
	PktCount                 uint64
	Tcp4PktCount             uint64
	Udp4PktCount             uint64
	OtherIp4ProtocolPktCount uint64
	FlowNotFound             uint64
	ErrInnerMapNotFound      uint64
	ErrCurrentCommFailed     uint64
	ErrInnerMapInsertFailed  uint64
}

// loadNf_bpf returns the embedded CollectionSpec for nf_bpf.
func loadNf_bpf() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_Nf_bpfBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load nf_bpf: %w", err)
	}

	return spec, err
}

// loadNf_bpfObjects loads nf_bpf and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*nf_bpfObjects
//	*nf_bpfPrograms
//	*nf_bpfMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadNf_bpfObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadNf_bpf()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// nf_bpfSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type nf_bpfSpecs struct {
	nf_bpfProgramSpecs
	nf_bpfMapSpecs
}

// nf_bpfSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type nf_bpfProgramSpecs struct {
	NfCount *ebpf.ProgramSpec `ebpf:"nf_count"`
}

// nf_bpfMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type nf_bpfMapSpecs struct {
	CountMap        *ebpf.MapSpec `ebpf:"count_map"`
	CounterMapOfMap *ebpf.MapSpec `ebpf:"counter_map_of_map"`
	MetricsMap      *ebpf.MapSpec `ebpf:"metrics_map"`
}

// nf_bpfObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadNf_bpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type nf_bpfObjects struct {
	nf_bpfPrograms
	nf_bpfMaps
}

func (o *nf_bpfObjects) Close() error {
	return _Nf_bpfClose(
		&o.nf_bpfPrograms,
		&o.nf_bpfMaps,
	)
}

// nf_bpfMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadNf_bpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type nf_bpfMaps struct {
	CountMap        *ebpf.Map `ebpf:"count_map"`
	CounterMapOfMap *ebpf.Map `ebpf:"counter_map_of_map"`
	MetricsMap      *ebpf.Map `ebpf:"metrics_map"`
}

func (m *nf_bpfMaps) Close() error {
	return _Nf_bpfClose(
		m.CountMap,
		m.CounterMapOfMap,
		m.MetricsMap,
	)
}

// nf_bpfPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadNf_bpfObjects or ebpf.CollectionSpec.LoadAndAssign.
type nf_bpfPrograms struct {
	NfCount *ebpf.Program `ebpf:"nf_count"`
}

func (p *nf_bpfPrograms) Close() error {
	return _Nf_bpfClose(
		p.NfCount,
	)
}

func _Nf_bpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed nf_bpf_bpfel.o
var _Nf_bpfBytes []byte
