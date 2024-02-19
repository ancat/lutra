package lutra

import (
    "bufio"
    "bytes"
    "crypto/sha1"
    "encoding/binary"
    "encoding/hex"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "sync"
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
    Inode             uint64
}

type Process struct {
    Pid               uint64
    Ppid              uint64
    Uid               uint32
    Filename          string
    Argv              uint64
    Mode              uint16
    Inode             uint64
}

type ProcessMap struct {
    mu        sync.Mutex
    entries map[uint64]Process
}

func NewProcessMap() *ProcessMap {
    return &ProcessMap{
        entries: make(map[uint64]Process),
    }
}

func (pm *ProcessMap) GetEntry(pid uint64) (Process, bool) {
    pm.mu.Lock()
    defer pm.mu.Unlock()

    entry, ok := pm.entries[pid]
    return entry, ok
}

func (pm *ProcessMap) AddOrUpdateEntry(p Process, notify chan uint64) {
    pm.mu.Lock()
    defer pm.mu.Unlock()

    existing, ok := pm.entries[p.Pid]
    // each process in the map is populated using two distinct events (pre/post execve)
    // if the pid, ppid, and uid match, it's safe to assume the two distinct events
    // refer to the same process. if there's a match, let's merge what
    // we just received into what we already have.
    // in situations I cannot explain, these events may arrive
    // in the wrong order
    if ok && existing.Pid == p.Pid && existing.Ppid == p.Ppid && existing.Uid == p.Uid {
        // Filename, Argv, Mode are part of the same event
        if len(existing.Filename) == 0 {
            existing.Filename = p.Filename
            existing.Argv = p.Argv
            existing.Mode = p.Mode
            pm.entries[p.Pid] = existing
            notify <- existing.Pid
        }

        // Inode is part of its own event
        if existing.Inode == 0 {
            existing.Inode = p.Inode
            pm.entries[p.Pid] = existing
            notify <- existing.Pid
        }
    } else {
        // whether the process exists or not, there's not a match
        // insert a new process.
        pm.entries[p.Pid] = p
    }
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

func contains(target uint64, arr []uint64) bool {
    for _, value := range arr {
        if value == target {
            return true
        }
    }
    return false
}

func calculateSHA1(filename string) (string, error) {
    file, err := os.Open(filename)
    if err != nil {
        return "", err
    }
    defer file.Close()

    hash := sha1.New()
    _, err = io.Copy(hash, file)
    if err != nil {
        return "", err
    }

    hashInBytes := hash.Sum(nil)
    hashString := hex.EncodeToString(hashInBytes)
    return hashString, nil
}

func ProcessExecs(receiver chan []byte, lost chan uint64) {
    populate_shells()
    processMap := NewProcessMap()
    notify := make(chan uint64)
    scanned_inodes := make([]uint64, 1000)
    signatures := make(map[string]string)
    signatures["2c336b35869a797d7c911b1986e2a80ae2dddca3"] = "socat lol"

    go func() {
        for { select {
            case pid, ok := <-notify:
                if !ok {
                    return
                }

                process, found := processMap.GetEntry(pid)
                if !found {
                    fmt.Printf("WHAT %d\n", pid);
                    continue
                }

                if contains(process.Inode, scanned_inodes) {
                    fmt.Printf(
                        "[pid=%d] [inode=%d] [%s] scanned already!\n",
                        process.Pid, process.Inode, process.Filename,
                    )

                    continue
                }

                fmt.Printf(
                    "[pid=%d] [inode=%d] [%s] scanning!\n",
                    process.Pid, process.Inode, process.Filename,
                )

                signature, err := calculateSHA1(process.Filename)
                if err != nil {
                    fmt.Printf("error with %s %s", process.Filename, err)
                    continue
                }

                description, match := signatures[signature]
                if match {
                    fmt.Printf(
                        "[pid=%d] [inode=%d] [%s] match - killing (%s)\n",
                        process.Pid, process.Inode, process.Filename,
                        description,
                    )
                } else {
                    fmt.Printf(
                        "[pid=%d] [inode=%d] [%s] good (for now,,,)\n",
                        process.Pid, process.Inode, process.Filename,
                    )

                    scanned_inodes = append(scanned_inodes, process.Inode)
                }
        }}
    }()

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
                // fmt.Printf("[%d] (%s) -> inode=%d/mode=%d\n", event.Pid, event.Filename, event.Inode, event.Mode)
                process := Process {
                    Pid: event.Pid,
                    Ppid: event.Ppid,
                    Filename: cleaned_filename,
                    Uid: event.Uid,
                    Argv: event.Argv,
                    Mode: event.Mode,
                    Inode: event.Inode,
                }
                processMap.AddOrUpdateEntry(process, notify)

                if is_a_shell(global_shells, cleaned_filename) {
                    if event.Mode == 49663 {
                        fmt.Printf("[+] shell detected pid=%d (%s) (socket stdin/stdout)\n", event.Pid, cleaned_filename)
                        // suspend_process(int(event.Pid))
                    } else if event.Envp == 0 {
                        fmt.Printf("[+] shell detected pid=%d (%s) (envp=NULL)\n", event.Pid, cleaned_filename)
                        // suspend_process(int(event.Pid))
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
