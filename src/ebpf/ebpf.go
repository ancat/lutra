package ebpf

import (
        _ "errors"
        "fmt"
        _ "syscall"
        _ "unsafe"

        _ "github.com/google/gopacket/afpacket"
        _ "github.com/google/gopacket/layers"
        _ "github.com/google/gopacket/pcap"
        _ "golang.org/x/net/bpf"
        "github.com/iovisor/gobpf/elf"
)

func LoadModuleElf(path string) (*elf.Module, error) {
    mod := elf.NewModule(path)
    if mod == nil {
        return nil, fmt.Errorf("failed to load elf at %s", path)
    }

    var secParams = map[string]elf.SectionParams{}

    if err := mod.Load(secParams); err != nil  {
        return nil, err
    }

    return mod, nil
}

func GetMap(
    module *elf.Module,
    map_name string,
    map_chan chan []byte,
    lost_chan chan uint64,
    ) error {
    event_table := module.Map(map_name)
    if event_table == nil {
        return fmt.Errorf("couldn't find map %s", map_name)
    }

    pm, _ := elf.InitPerfMap(module, map_name, map_chan, lost_chan)
    pm.PollStart()

    return nil
}
