module github.com/ancat/lutra

go 1.13

require github.com/ancat/lutra/src v0.0.0

replace github.com/ancat/lutra/src v0.0.0 => ./src

require (
	github.com/google/gopacket v1.1.17
	github.com/iovisor/gobpf v0.2.0
	github.com/sirupsen/logrus v1.4.2
	golang.org/x/net v0.0.0-20211123203042-d83791d6bcd9
	gopkg.in/yaml.v2 v2.2.8
)
