# eBPF XDP App

An HTTP server that displays received packets from kernel space and allows blocking of specified IP addresses.

## Components

### `ipblocker.c`
A kernel-space program that parses packets and maintains two lists:
- Blocked list
- Received list

### `gen.go`
A script for generating Go code from C code.

### `main.go`
A user-space program that:
- Displays packets
- Hosts an HTTP server
- Handles logic for listing and adding blocked IP addresses

## How to Run

### Using Makefile

```bash
make build   # Generate Go code and the executable binary
make run     # Run the program
```

### Manually

```bash
go generate  # Generate Go code from C code
go build     # Build the executable binary
sudo ./ipblocker-ebpf-xdp  # Run the program with elevated privileges
```

## Requirements 
Ensure the following are installed:
- Linux kernel 5.7 or later
- LLVM 11 or later
- libbpf headers
- Linux kernel headers
- Go compiler

Refer to [cilium/ebpf](https://ebpf-go.dev/)