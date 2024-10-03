package entity

type SockReader interface {
	Read() (map[PID]SockInfo, error)
	Close() error
}

type PID uint64

type SockInfo struct {
	PID         PID
	ProcessName string
	Bytes       uint64
}
