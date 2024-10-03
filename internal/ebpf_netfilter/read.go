package ebpf_netfilter

import (
	"github.com/teja2010/epnetmon/internal/entity"
)

type reader struct{}

func NewEbpfNetfilterReader() entity.SockReader {
	return &reader{}
}

func (enr *reader) Read() (map[entity.PID]entity.SockInfo, error) {
	return nil, nil
}

func (enr *reader) Close() error {
	return nil
}
