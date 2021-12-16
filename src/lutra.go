package lutra

import (
    "bufio"
    "bytes"
    "encoding/binary"
    "fmt"
    "os"
    "path/filepath"
)

type ExecEvent struct {
    Pid               uint64
    Ppid              uint64
    Comm              [16]byte
    Filename          [256]byte
    Uid               uint32
    Argv              uint64
    Envp              uint64
    Mode              uint16
}

var global_shells []string
func populate_shells() {
    shells, err := os.Open("/etc/shells")
    if err != nil {
        global_shells = []string{"/bin/sh", "/bin/bash"}
        return
    }

    scanner := bufio.NewScanner(shells)
    var shell string
    for scanner.Scan() {
        shell = scanner.Text()
        if shell[0] == '#' {
            continue
        }

        global_shells = append(global_shells, shell)
    }
}

func ProcessExecs(receiver chan []byte, lost chan uint64) {
    populate_shells()

    for {
        select {
        case data, ok := <-receiver:
            if !ok {
                return
            }

            buffer := bytes.NewBuffer(data)
            var event ExecEvent
            err := binary.Read(buffer, binary.LittleEndian, &event)
            if err != nil {
                panic(err)
            }

            go func() {
                // surely there's a better way to create a null terminated string
                cleaned_filename := filepath.Clean(string(bytes.Trim(event.Filename[:], "\000")))
                if is_a_shell(global_shells, cleaned_filename) {
                    if event.Mode == 49663 {
                        fmt.Printf("[+] shell detected pid=%d (%s) (socket stdin/stdout)\n", event.Pid, cleaned_filename)
                        suspend_process(int(event.Pid))
                    } else if event.Envp == 0 {
                        fmt.Printf("[+] shell detected pid=%d (%s) (envp=NULL)\n", event.Pid, cleaned_filename)
                        suspend_process(int(event.Pid))
                    }
                } else {
                    fmt.Printf("not a shell %s\n", cleaned_filename)
                }

            }()
        case _, ok := <-lost:
            if !ok {
                return
            }
        }
    }
}

func is_a_shell(shells []string, shell string) bool {
    for _, s := range shells {
        if string(s) == string(shell) {
            return true
        }
    }

    return false
}
