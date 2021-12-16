package main

import (
    "fmt"

    lutra "github.com/ancat/lutra/src"
)

func main() {
    fmt.Printf("hello :)\n")
    channel, lost_chan := load_ebpf_module("ebpf/watcher.o")
    lutra.ProcessExecs(channel, lost_chan)
}
