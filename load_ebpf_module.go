package main

import (
    ebpf "github.com/ancat/lutra/src/ebpf"
	log "github.com/sirupsen/logrus"
)

func load_ebpf_module(path string) (chan []byte, chan uint64) {
    mod, err := ebpf.LoadModuleElf(path)
    if err != nil {
        log.Fatalf("Failed to load ebpf binary: %s", err)
    }

	if err := mod.EnableKprobe("kprobe/sys_execve", 1); err != nil {
		log.Fatalf("Failed to set up kprobes: %s\nMake sure you are running as root and that debugfs is mounted!", err)
	}

    channel := make(chan []byte)
    lost_chan := make(chan uint64)
    err = ebpf.GetMap(mod, "events", channel, lost_chan)
	if err != nil {
		log.Fatalf("Failed to load exec events map: %s", err)
	}


    return channel, lost_chan
}
