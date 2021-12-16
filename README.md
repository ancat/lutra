# lutra

Otters are notable for being one of the few animals that use tools, in particular rocks to break shells. Coincidentally, this program does the same thing!

## But actually?

This program uses an ebpf program to watch for shells spawning that match one of two criteria:

* Shells spawned where the envp parameter to execve is NULL (most intel based linux shellcode does this to save space)
* Shells spawned where any of the file descriptors are sockets (most reverse shells)

The logic for determining these two values is done entirely in ebpf. This has the benefit of both being faster than doing it in userland, and also doesn't need procfs (which on its own is already slow and error prone)

When either of these criteria is met, the [freezer subsystem](https://www.kernel.org/doc/Documentation/cgroup-v1/freezer-subsystem.txt) is used to suspend the process, rendering the shell useless but in a state where it can be inspected as is. Sending a SIGSTOP is just as uncatchable and achieves the same goal but has some limitations:

* SIGSTOP can be observed by userland code (how many maliciously spawned shells will do this? probably none)
* Freezer can stop all processes belonging to the same cgroup all at once, super useful for containers where you might want to preserve the entire state of the container instead of just the shell
* SIGSTOP processes can be killed (i.e. attacker wants to remove their shell), frozen processes cannot without being thawed first (even by root!)
* Freezer by definition is literally cooler

## Building

* To build everything: `make`
* To work on the ebpf code and rebuild just that: `make build-ebpf-object`
* To work on the go code: `make lutra-main`

## Launching

* `make`
* `sudo ./lutra`
