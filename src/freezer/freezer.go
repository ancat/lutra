package freezer

import (
    "bufio"
    "bytes"
    "fmt"
    "os"
    "strings"
)

func rain() {
    pid := 1950
    fmt.Println("Hello, it is i")
    cgroup_name := GetFreezerInfo(pid)
    fmt.Printf("cgroup for pid %d=%s\n", pid, cgroup_name)
    UpdateFreezerTasks("hehehe", []int{pid})
    if GetFreezerStateByName(cgroup_name) == "" {
        fmt.Printf("we r panic\n")
    }
    fmt.Printf("state for pid %d=%s\n", pid, GetFreezerStateByName(cgroup_name))
    fmt.Printf("state for pid %d=%s\n", pid, GetFreezerStateByPid(pid))
    UpdateFreezerStateByName("hehehe", "THAWED")
}

/*
  5 def get_cgroup_info(pid):
  6     cgroup_info = ""
  7     with open(f"/proc/{pid}/cgroup") as fh:
  8         for line in fh:
  9             (num, group, value) = line.strip().split(":", 3)
 10             if group == "freezer":
 11                 return value
*/

func GetFreezerInfo(pid int) string {
    handle, err := os.Open(fmt.Sprintf("/proc/%d/cgroup", pid))
    if err != nil {
        panic(err)
    }

    defer handle.Close()
    scanner := bufio.NewScanner(handle)

    for scanner.Scan() {
        s := strings.SplitN(scanner.Text(), ":", 3)
        if s[1] == "freezer" {
            return s[2]
        }
    }

    return ""
}

/*
 13 def update_freezer_cgroup(name, pids=[]):
 14     freezer_path = f"/sys/fs/cgroup/freezer/{name}"
 15     try:
 16         os.mkdir(freezer_path)
 17     except FileExistsError:
 18         pass
 19
 20     with open(f"{freezer_path}/tasks", "w") as fh:
 21         for pid in pids:
 22             fh.write(f"{pid}\n")
*/
func UpdateFreezerTasks(name string, pids []int) {
    err := os.MkdirAll(fmt.Sprintf("/sys/fs/cgroup/freezer/%s", name), 0755)
    if err != nil {
        panic(err)
    }

    handle, err := os.OpenFile(fmt.Sprintf("/sys/fs/cgroup/freezer/%s/tasks", name), os.O_RDWR|os.O_CREATE, 0755)
    if err != nil {
        panic(err)
    }
    defer handle.Close()

    for _, pid := range pids {
        handle.WriteString(fmt.Sprintf("%d\n", pid))
    }
}

/*
 24 def get_freezer_state_by_cgroup(name):
 25     freezer_path = f"/sys/fs/cgroup/freezer/{name}"
 26
 27     with open(f"{freezer_path}/freezer.state") as fh:
 28         return fh.read().strip()
*/
func GetFreezerStateByName(name string) string {
    state, err := os.ReadFile(fmt.Sprintf("/sys/fs/cgroup/freezer/%s/freezer.state", name))
    if err != nil {
        panic(err)
    }

    return string(bytes.TrimSpace(state))
}

/*
 30 def get_freezer_state_by_pid(pid):
 31     return get_freezer_state_by_cgroup(get_cgroup_info(pid))
*/
func GetFreezerStateByPid(pid int) string {
    return GetFreezerStateByName(GetFreezerInfo(pid))
}

/*
 33 def update_freezer_state_by_cgroup(name, state):
 34     if state not in ["THAWED", "FROZEN"]:
 35         raise ValueError(f"State must be THAWED or FROZEN, not {state}")
 36     freezer_path = f"/sys/fs/cgroup/freezer/{name}"
 37
 38     with open(f"{freezer_path}/freezer.state", "w") as fh:
 39         return fh.write(f"{state}\n")
*/
func UpdateFreezerStateByName(name string, state string) {
    handle, err := os.OpenFile(fmt.Sprintf("/sys/fs/cgroup/freezer/%s/freezer.state", name), os.O_RDWR, 0755)
    if err != nil {
        panic(err)
    }
    defer handle.Close()

    handle.WriteString(fmt.Sprintf("%s\n", state))
}

/*
 41 def update_freezer_state_by_pid(pid, state):
 42     return update_freezer_state_by_cgroup(get_cgroup_info(pid), state)
*/
func UpdateFreezerStateByPid(pid int, state string) {}
