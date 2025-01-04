package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type request struct {
	IpAddr string `json:"ip_addr"`
}

type response struct {
	Message  string   `json:"message,omitempty"`
	Response []string `json:"response,omitempty"`
}

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal("Removing memlock:", err)
	}

	var objs ipblockerObjects
	if err := loadIpblockerObjects(&objs, nil); err != nil {
		log.Fatal("Loading eBPF objects:", err)
	}
	defer objs.Close()

	ifname := "wlp0s20f3"
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProgFunc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatal("Attaching XDP:", err)
	}
	defer link.Close()

	http.HandleFunc("/list", func(w http.ResponseWriter, r *http.Request) {
		list := make([]string, 0, 128)

		var key netip.Addr
		var val uint32
		iter := objs.RecievedIps.Iterate()
		for iter.Next(&key, &val) {
			list = append(list, fmt.Sprintf("%s => %d", key, val))
		}

		res := &response{
			Response: list,
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(res); err != nil {
			return
		}
	})

	http.HandleFunc("/add", func(w http.ResponseWriter, r *http.Request) {
		var req request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Fatal("Failed to parse request")
			return
		}

		blockIP := req.IpAddr
		ip := binary.BigEndian.Uint32(net.ParseIP(blockIP).To4())
		if err := objs.BlockedIps.Put(ip, uint32(1)); err != nil {
			log.Fatalf("Failed to add IP to map: %v", err)
			return
		}

		res := &response{
			Message: "Successfully added.",
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(res); err != nil {
			return
		}
	})

	http.ListenAndServe(":8000", nil)
}
