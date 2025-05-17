package network

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"time"

	"github.com/lilendian0x00/xray-knife/v3/utils/customlog"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type IcmpPacket struct {
	DestIP                 net.IP
	CustomInternetProtoID  int
	CustomSequenceNum      int
	Data                   []byte
	TestCount              uint16
	DelayBetweenEachPacket uint16
}

type IcmpPacketOption = func(c *IcmpPacket)

func NewIcmpPacket(dest string, count uint16, opts ...IcmpPacketOption) (*IcmpPacket, error) {
	i := &IcmpPacket{
		TestCount: count,
	}
	for _, opt := range opts {
		opt(i)
	}

	i.DestIP = net.ParseIP(dest)
	if i.DestIP == nil {
		addr, err := net.LookupIP(dest)
		if err != nil {
			return nil, err
		}
		i.DestIP = addr[0]
	}
	return i, nil
}

func (i *IcmpPacket) MeasureReplyDelay() error {
	rnd := rand.New(rand.NewSource(time.Now().Unix()))

	if i.DestIP == nil {
		customlog.Printf(customlog.Failure, "Destination IP address is empty!\n")
		return errors.New("Destination IP address is empty! ")
	}
	if i.CustomInternetProtoID == 0 {
		i.CustomInternetProtoID = os.Getpid() & 0xffff
	}
	if i.CustomSequenceNum == 0 {
		i.CustomSequenceNum = rnd.Intn(4294967290)
	}
	if len(i.Data) == 0 {
		// Windows default DATA
		data := []byte("abcdefghijklmnopqrstuvwabcdefghi")
		buf := bytes.NewReader(data)
		i.Data = make([]byte, 32)
		err := binary.Read(buf, binary.LittleEndian, i.Data)
		if err != nil {
			customlog.Printf(customlog.Failure, "binary.Read failed: %v\n", err)
			return err
		}
	}
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		customlog.Printf(customlog.Failure, "listen err: %v\n", err)
		return err
	}
	defer c.Close()

	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: i.CustomInternetProtoID, Seq: i.CustomSequenceNum,
			Data: i.Data,
		},
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		return err
	}
	// Record the current time
	start := time.Now()

	msg := make(chan int)
	errMsg := make(chan string)
	//done := make(chan bool, 1)
	go func() {
		for a := 0; a < 5; a++ {
			_, err = c.WriteTo(wb, &net.IPAddr{IP: i.DestIP})
			start = time.Now()
			if err != nil {
				msg <- -1
				errMsg <- fmt.Sprintf("WriteTo err: %s", err.Error())
			} else {
				msg <- 0
			}
			time.Sleep(time.Duration(1) * time.Second)
		}
		msg <- 1
	}()

	for m := range msg {
		if m == 0 {
			rb := make([]byte, 1500)
			n, peer, err1 := c.ReadFrom(rb)
			if err1 != nil {
				customlog.Printf(customlog.Failure, "Error ReadFrom: %v\n", err1)
				return err
			}
			rm, err2 := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), rb[:n])
			if err2 != nil {
				customlog.Printf(customlog.Failure, "Error icmp.ParseMessage: %v\n", err2)
				return err
			}
			switch rm.Type {
			case ipv4.ICMPTypeEchoReply:
				customlog.Printf(customlog.Success, "Reply from %s: bytes=32 time=%dms\n", peer, time.Since(start).Milliseconds())
				break
			default:
				customlog.Printf(customlog.Failure, "Got %+v\n", rm)
			}
		} else if m == -1 {
			// Error happened
			sendErr := <-errMsg
			customlog.Printf(customlog.Failure, "%s\n", sendErr)
		} else {
			break
		}
	}
	return nil
}
