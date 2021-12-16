package lutra

import (
    freezer "github.com/ancat/lutra/src/freezer"
)

func suspend_process(pid int) {
    freezer_name := freezer.GetFreezerInfo(pid)
    if freezer_name == "/" {
        freezer_name = "lutrafreeze"
        freezer.UpdateFreezerTasks(freezer_name, []int{pid})
    }

    freezer.UpdateFreezerStateByName(freezer_name, "FROZEN")
}
