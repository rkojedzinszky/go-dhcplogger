package main

import (
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/insomniacslk/dhcp/dhcpv4"
	_ "github.com/lib/pq"
)

// Feeder parses & feeds received packets to SQL
type Feeder struct {
	db   *sql.DB
	stmt *sql.Stmt

	queue   chan gopacket.Packet
	workers sync.WaitGroup
	retries int
}

// New instantiates a new Feeder
func newFeeder(dbhost string, dbport int, dbuser string, dbpassword string, dbname string, maxQueueLength int, retries int) (*Feeder, error) {
	db, err := sql.Open(
		"postgres",
		fmt.Sprintf(
			"host=%s port=%d user=%s password=%s database=%s sslmode=disable",
			dbhost, dbport, dbuser, dbpassword, dbname,
		),
	)

	if err != nil {
		return nil, err
	}

	stmt, err := db.Prepare("INSERT INTO dhcp4_log (ts, client, agent, ip, leasetime, packet) VALUES ($1, $2, $3, $4, $5, $6)")
	if err != nil {
		db.Close()
		return nil, err
	}

	return &Feeder{
		db:      db,
		stmt:    stmt,
		queue:   make(chan gopacket.Packet, maxQueueLength),
		retries: retries,
	}, nil
}

// Close closes feeder
func (f *Feeder) Close() {
	close(f.queue)
	f.workers.Wait()
	f.stmt.Close()
	f.db.Close()
}

// Run starts the specified number of workers
func (f *Feeder) Run(workers int) {
	f.workers.Add(workers)
	for i := 0; i < workers; i++ {
		go f.worker()
	}
}

func (f *Feeder) worker() {
	defer f.workers.Done()

	for packet := range f.queue {
		f.processPacket(packet)
	}
}

func (f *Feeder) processPacket(packet gopacket.Packet) {
	dhcpPacket, err := dhcpv4.FromBytes(packet.TransportLayer().LayerPayload())
	if err != nil {
		fmt.Print(err)
		return
	}

	if dhcpPacket.MessageType() != dhcpv4.MessageTypeAck {
		return
	}

	ts := time.Now()

	client := dhcpPacket.ClientHWAddr.String()
	var agent sql.NullString

	relayInfo := dhcpPacket.RelayAgentInfo()
	if relayInfo != nil {
		agent.String = net.HardwareAddr(relayInfo.Options.Get(dhcpv4.AgentRemoteIDSubOption)).String()
		agent.Valid = true
	}

	yourip := dhcpPacket.YourIPAddr.String()

	var leaseTime sql.NullInt32
	leaseTimeRaw := dhcpPacket.Options.Get(dhcpv4.OptionIPAddressLeaseTime)
	if len(leaseTimeRaw) == 4 {
		leaseTime.Int32 = int32(binary.BigEndian.Uint32(leaseTimeRaw))
		leaseTime.Valid = true
	}

	var buf []byte
	if buf, err = json.Marshal(dhcpPacket); err != nil {
		fmt.Println("Failed to json.Marshal dhcp packet: ", err)
	}

	i := 0
	for {
		_, err := f.stmt.Exec(ts, client, agent, yourip, leaseTime, buf)
		if err == nil {
			return
		}

		if i == f.retries {
			log.Printf("%s/%s: max retries exhausted, dropping packet\n", client, yourip)
			return
		}

		i++
		time.Sleep(time.Second)
	}
}
