package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"time"

	"github.com/charmbracelet/log"
	"github.com/teja2010/epnetmon/internal/ebpf_netfilter"
	"github.com/teja2010/epnetmon/internal/entity"
	"github.com/teja2010/epnetmon/internal/util"
)

func main() {
	{ // setup logs
		f, err := os.OpenFile("/tmp/epnetmon.log", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			log.Fatal("Failed to open log file", err)
			return
		}
		defer f.Close()
		log.SetOutput(f)
		log.SetReportTimestamp(true)
		log.SetReportCaller(true)
		log.Info("epnetmon started")
	}

	var (
		debug       bool
		backend     string
		intervalArg string
	)
	flag.BoolVar(&debug, "debug", false, "enable debug logs")
	flag.StringVar(&backend, "b", "ebpf_nft", "choose a backend (ebpf_nft|nft|sock_diag|ebpf)")
	flag.StringVar(&intervalArg, "i", "1s", "refresh interval e.g 1s, 250ms, 1min")

	if debug {
		log.SetLevel(log.DebugLevel)
	}
	interval, err := util.ParseInterval(intervalArg)
	if err != nil {
		log.Fatal("Error parsing interval", "error", err)
	}

	var sr entity.SockReader
	switch backend {
	case "ebpf_nft":
		sr = ebpf_netfilter.NewEbpfNetfilterReader()
	}
	defer sr.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ticker := time.NewTicker(interval)

	for {
		select {
		case <-ticker.C:
			_, _ = sr.Read()
		case <-ctx.Done():
			return
		}
	}
}
