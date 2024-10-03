package main

import (
   	"flag"
   	"fmt"
	"os"
	"bufio"
	"log"
	"time"
	"errors"
	"net"
	"strings"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	"sync"
	 

)

var (
	handle *pcap.Handle
	err error
	myIP1 net.IP
	fileExist bool
)


type hostNames struct {
	hostIP net.IP
	hostname string
}

func main() {
	fileExist = false	
	address, err := externalIP()
				if err != nil {
					fmt.Println(err)
				}
	
	myIP1=net.ParseIP(address)
	
	loc, err := time.LoadLocation("America/New_York")
   	if err != nil {
			log.Fatal(err)
		}
   	 time.Local = loc
	 
   
    interfaces := flag.String("i", "", "Network interface name")
    filename := flag.String("f", "", "A list of IP address and hostname pairs")
    flag.Parse()
/// read from file
    var hostnames []hostNames
	
	if *filename != "" {
		fileExist =true
		file, err := os.Open(*filename)
		if err != nil {
			log.Fatal(err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		var tmp []string
		i:=0
		var tmphost hostNames
		
		for scanner.Scan() {
			
			tmp=strings.Fields(scanner.Text())
			
			if len(tmp)== 2 {
			 tmpip := net.ParseIP(tmp[0])
				if err != nil {
					log.Fatal(err)
				}
				tmphost.hostIP = tmpip
				tmphost.hostname=tmp[1]
				hostnames=append(hostnames,tmphost)
				i=i+1
			}else {
				fmt.Println("The file format is incorrect!")
				log.Fatal(err)
			}
			
		 }
	

    if err := scanner.Err(); err != nil {
        log.Fatal(err)
    }
	} 
	if *interfaces == "" {	    
	  tmp:=livedevice()
		if len(tmp)==1 {
		 *interfaces=tmp[0]
		} else if len(tmp) == 0 {
		 fmt.Println("There is not an active interface on your system !! Please enable one interface and excute the program again :)")
		 log.Fatal(err)
		} else if len(tmp)>2 {
		fmt.Println("There is more than one active interface please choose one and give the program with -i option or disable them except your desired one :)")	
		log.Fatal(err)
		}
	}

	

	if *interfaces != ""{
		var (
		 snaplen int32 = 65535
		 promisc bool = true
		 timeout time.Duration = -1 * time.Second
		)
		handle, err = pcap.OpenLive(*interfaces, snaplen, promisc, timeout)
		if err != nil {
			log.Fatal(err)
		}
		
	}
	
	if len(flag.Args()) > 0 {
	 bpfFilter:=flag.Args()
	 filter := strings.Join(bpfFilter, " ")
	 err = handle.SetBPFFilter("udp and port 53 and "+filter)
	  if err != nil {
	 	log.Fatal(err)
	  }
	}else {
		err = handle.SetBPFFilter("udp and port 53")
	  if err != nil {
	 	log.Fatal(err)
	  }
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	var wg sync.WaitGroup
	for packet := range packetSource.Packets() {

		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer != nil {
			dns := dnsLayer.(*layers.DNS)
			if dns.QR {
			if fileExist {
			for i := 0; i < len(hostnames); i++ {
				if strings.Contains(string(dns.Questions[0].Name), hostnames[i].hostname ) {
				wg.Add(1)
				go handlePacket(handle,dns,packet,hostnames[i].hostIP, &wg)
				} else {
					continue
				}
			}
			
			} else {
				wg.Add(1)
				go handlePacket(handle,dns,packet,myIP1, &wg)
			}
			}
}
		
}	
		wg.Wait()

 
}

func handlePacket (handle *pcap.Handle,dns *layers.DNS, packet gopacket.Packet, myIP net.IP,wg *sync.WaitGroup){
			defer wg.Done()
			
			/*
			answers := make([]layers.DNSResourceRecord, 0)
				for i := 0; i < len(dns.Answers); i++ { 
				answers = append(answers,
					dns.Answers[i])
				}*/
				newdns := layers.DNS{
					ID:           dns.ID,
					QR:           dns.QR,
					OpCode:       dns.OpCode,
					QDCount:      dns.QDCount,
					ANCount:      dns.ANCount,
					NSCount:      dns.NSCount,
					ARCount:      dns.ARCount,
					Questions:    dns.Questions,
					Additionals:  dns.Additionals,
					Answers:      dns.Answers,
				    AA:           dns.AA,
					TC:           dns.TC,
					RD:           dns.RD,
					RA:           dns.RA,
					Z:            dns.Z,
					ResponseCode: dns.ResponseCode,
				}
				
			   ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		
				ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
				
				eth := layers.Ethernet{
						SrcMAC:        net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
						DstMAC:        ethernetPacket.DstMAC,
						EthernetType:  layers.EthernetTypeIPv4,
			
				}
			//	fmt.Println(ethernetPacket.SrcMAC)
				ipLayer := packet.Layer(layers.LayerTypeIPv4)
				ipt, _ := ipLayer.(*layers.IPv4)
				ipv4 := layers.IPv4{
					Version:  4,
					TTL:      64,
					SrcIP:    ipt.SrcIP,
					DstIP:    ipt.DstIP,
					Protocol: layers.IPProtocolUDP,
					}
					
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			udps, _ := udpLayer .(*layers.UDP)
			udp := layers.UDP{
			  SrcPort: udps.SrcPort,
			   DstPort: udps.DstPort,
				}
			udp.SetNetworkLayerForChecksum(&ipv4)
			
			buf := gopacket.NewSerializeBuffer()
			opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
			}
			gopacket.SerializeLayers(buf, opts,
				&eth,
				&ipv4,
				&udp,
				&newdns,
				)
			outgoingPacket := buf.Bytes()
			if err = handle.WritePacketData(outgoingPacket); err != nil {
				panic(err)
				}
			
			
}
	
func livedevice() []string {
    devs, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	var live []string
	for _, i := range devs {
		devfind := false
		var addrs []string
		for _, addr := range i.Addresses {
			if addr.IP.IsLoopback() || addr.IP.IsMulticast() || addr.IP.IsUnspecified() || addr.IP.IsLinkLocalUnicast() {
				continue
			}
			devfind = true
			addrs = append(addrs, addr.IP.String())
		}
		if devfind {
			live = append(live, i.Name)
		}
	}
		return live
	

}
func externalIP() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return "", err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}
			return ip.String(), nil
		}
	}
	return "", errors.New("are you connected to the network?")
}

