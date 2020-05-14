package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/namsral/flag"
)

func main() {
	iface := flag.String("interface", "", "Interface to capture packets on")
	dbHost := flag.String("dbhost", "postgres", "PostgresSQL host")
	dbPort := flag.Int("dbport", 5432, "PostgreSQL port")
	dbUser := flag.String("dbuser", "dhcplogger", "PostgreSQL user")
	dbPassword := flag.String("dbpassword", "dhcplogger", "PostgreSQL password")
	dbName := flag.String("dbname", "dhcplogger", "PostgreSQL database name")
	workers := flag.Int("workers", 4, "Number of goroutines handling packets")
	retries := flag.Int("retries", 30, "Retry count for sql operations")
	maxQueueLength := flag.Int("max-queue-length", 1000, "Maximum number of dhcp packets to hold in queue")

	flag.Parse()

	if *iface == "" {
		panic(fmt.Errorf("No interface specified"))
	}

	feeder, err := newFeeder(*dbHost, *dbPort, *dbUser, *dbPassword, *dbName, *maxQueueLength, *retries)
	if err != nil {
		panic(err)
	}

	feeder.Run(*workers)

	handle, err := pcap.OpenLive(*iface, 1600, false, pcap.BlockForever)
	if err != nil {
		panic(err)
	}

	// Filter for bootp reply packets
	if err := handle.SetBPFFilter("udp and src port 67 and udp[8:1] == 2"); err != nil {
		panic(err)
	}

	ps := gopacket.NewPacketSource(handle, handle.LinkType())
	pchan := ps.Packets()

	termsig := make(chan os.Signal)
	signal.Notify(termsig, syscall.SIGTERM, syscall.SIGINT)

LOOP:
	for {
		select {
		case raw := <-pchan:
			select {
			case feeder.queue <- raw:
			default:
				log.Println("Queue overflow")
			}
		case <-termsig:
			break LOOP
		}
	}

	fmt.Println("Exiting...")
	handle.Close()
	feeder.Close()
}
