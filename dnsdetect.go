package main

import (
   	"fmt"
	"flag"
	"log"
	"time"
	"strings"	
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/layers"
	"sync"
	"os"
	
)
var (
	handle *pcap.Handle
	err error
	mpacket map[int]DnsPack
	wg sync.WaitGroup
)
type DnsPack struct {
	Timestamp       time.Time
	aNames			[]string
	domain			string	
	rcount			int
	qcount			int
}

func main() {
	loc, err := time.LoadLocation("America/New_York")
   	if err != nil {
			log.Fatal(err)
		}
   	 time.Local = loc
	 interfaces := flag.String("i", "", "Network interface name")
	 filename := flag.String("r", "", "Offline captured file's name")
	 flag.Parse()
	
	if *interfaces != "" && *filename != ""  {
       fmt.Printf("You can only use one option online or offline capture!\n")
	   flag.PrintDefaults()
	    os.Exit(1)
    }
	
//find an active interface 
	if *interfaces == "" && *filename == ""{	    
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
	} else if *filename != "" {
		handle, err = pcap.OpenOffline(*filename)
		if err != nil {
			log.Fatal(err)
		}
	}


//The following code can be used to read in data from an interface
	if *interfaces != ""{
		var (
		 snaplen int32 = 65535
		 promisc bool = false
		 timeout time.Duration = -1 * time.Second
		)
		handle, err = pcap.OpenLive(*interfaces, snaplen, promisc, timeout)
		if err != nil {
			log.Fatal(err)
		}
		
	}

//The following code can be used to read in data from the pcap file
	
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
	mpacket = make(map[int]DnsPack)
	go deletepacket()
	 readpacket()
	
}

func readpacket(){
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	
	for packet := range packetSource.Packets() {
		dnsLayer := packet.Layer(layers.LayerTypeDNS)
		if dnsLayer != nil {
			dns := dnsLayer.(*layers.DNS)
			if !dns.QR {
				addpacket(dns,packet.Metadata().Timestamp)
			}else {
				comparepacket(dns,packet.Metadata().Timestamp)
			}
		}
	}
	
	
}
func addpacket(dns *layers.DNS, time time.Time ){
	
	if tmpdns, ok := mpacket[int(dns.ID)]; ok {
		tmpdns.Timestamp=time
		tmpdns.qcount=tmpdns.qcount+1
		mpacket[int(dns.ID)]=tmpdns

	 } else {
		tmpdns.qcount=1
		tmpdns.domain=fmt.Sprintf("%s",dns.Questions[0].Name)
		tmpdns.Timestamp=time
		mpacket[int(dns.ID)]=tmpdns
	}
	
}

func comparepacket(dns *layers.DNS,time time.Time){

	if tmpdns, ok := mpacket[int(dns.ID)]; ok {
		
		if tmpdns.rcount == tmpdns.qcount {
			attackdetect(tmpdns, dns,time)
			
		}else if tmpdns.rcount < tmpdns.qcount {
			
			var tmpstr string =""
			for i:=0; i < len(dns.Answers); i++ {	
				if dns.Answers[i].Type.String()=="CNAME"{
				  if tmpstr!="" {
				  tmpstr=tmpstr+","+fmt.Sprintf("%s",dns.Answers[i].CNAME)
				  }else {
					tmpstr=fmt.Sprintf("%s",dns.Answers[i].CNAME)  
				  }
				
				} else if tmpstr != "" {
					tmpstr=tmpstr+","+fmt.Sprintf("%s",dns.Answers[i].IP) 
					} else {
					 tmpstr=fmt.Sprintf("%s",dns.Answers[i].IP) 
					}
				
				}
			
			tmpdns.aNames=append(tmpdns.aNames,tmpstr)
			tmpdns.rcount=tmpdns.rcount+1
			mpacket[int(dns.ID)]=tmpdns
		}
		
	} else {
		fmt.Println("Illegal packet detect: the request packet has not received!")
	}
	
	
}
func attackdetect (tmpdnso DnsPack,dns *layers.DNS, time time.Time){
	
		var tmpdns DnsPack
		if len(dns.Answers)>0 {
		 tmpdns.domain=fmt.Sprintf("%s",dns.Answers[0].Name)
		}
		tmpdns.Timestamp=time
		var tmpstr string=""
			for i:=0; i < len(dns.Answers); i++ {	
				if dns.Answers[i].Type.String()=="CNAME"{
				  if tmpstr!="" {
				  tmpstr=tmpstr+","+fmt.Sprintf("%s",dns.Answers[i].CNAME)
				  }else {
					tmpstr=fmt.Sprintf("%s",dns.Answers[i].CNAME)  
				  }
				
				} else if tmpstr != "" {
					tmpstr=tmpstr+","+fmt.Sprintf("%s",dns.Answers[i].IP) 
					} else {
					 tmpstr=fmt.Sprintf("%s",dns.Answers[i].IP) 
					}
				
				}
				
				
				
		tmpdns.aNames=append(tmpdns.aNames,tmpstr)
		
		var domb bool=false
		for _, dom1 := range tmpdnso.aNames {
		 for _, dom2 := range tmpdns.aNames {
			if dom1==dom2 {
				domb=true
			}
		 }
		}
		
		var attackb bool=true
		if tmpdns.domain == tmpdnso.domain {
			if !domb {
			attackb=true
			} else {
			attackb=false
			}
			}else {
			attackb=false
			}
	 
			if attackb {
			wg.Add(1)
			printattack(int(dns.ID),tmpdnso,tmpdns)
			wg.Wait()
			}
			
}

func deletepacket () {
	  for _ = range time.Tick(10 * time.Second) {
			now:=time.Now()
			for id, dnspacket := range mpacket {
				diff := now.Sub(dnspacket.Timestamp)
				second := int(diff.Seconds())
				if second > 5 {
					delete(mpacket,id)
				}
			}
        }
	
}

func printattack (id int, origin DnsPack, attack DnsPack) {
	defer wg.Done()
		fmt.Printf("%s DNS poisoning attempt\n",attack.Timestamp)
		fmt.Printf("TXID %d  Request %s \n",id,origin.domain)
		fmt.Printf("Answer1 (%d answer(s)) %s \n", len(origin.aNames), origin.aNames)
		fmt.Printf("Answer2 (%d answer(s)) %s \n", len(attack.aNames),attack.aNames)
		fmt.Println("---------------------------------------------------------------------------")

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

	
