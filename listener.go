package main


import (
  "log"
  "github.com/google/gopacket"
  "github.com/google/gopacket/pcap"
  "fmt"
  "time"
  "github.com/google/gopacket/layers"
  "strings"
)


// Layers that we care about decoding
var (
	eth     layers.Ethernet
	ip      layers.IPv4
	tcp     layers.TCP
	udp     layers.UDP
	icmp    layers.ICMPv4
	dns     layers.DNS
	payload gopacket.Payload
)


// libpcap version of the gopacket library
type PcapSniffer struct {
	handle *pcap.Handle
}


func (s *PcapSniffer) Open(iface string) error {
	// Capture settings
	const (
		// Max packet length
		snaplen int32 = 65536
		// Set the interface in promiscuous mode
		promisc bool = true
		// Timeout duration
		flushAfter string = "10s"
		//BPF filter when capturing packets
		filter string = "tcp"
	)

	// Open the interface
	flushDuration, err := time.ParseDuration(flushAfter)
	if err != nil {
		return fmt.Errorf("Invalid flush duration: %s", flushAfter)
	}
	handle, err := pcap.OpenLive(iface, snaplen, promisc, flushDuration/2)
	if err != nil {
		return fmt.Errorf("Error opening pcap handle: %s", err)
	}
	if err := handle.SetBPFFilter(filter); err != nil {
		return fmt.Errorf("Error setting BPF filter: %s", err)
	}
	s.handle = handle

	return nil
}

func (s *PcapSniffer) Close() {
	s.handle.Close()
}

func (s *PcapSniffer) ReadPacket() (data []byte, ci gopacket.CaptureInfo, err error) {
	return s.handle.ZeroCopyReadPacketData()
}


func handlePacket(decodedLayers []gopacket.LayerType, ci gopacket.CaptureInfo, appGlobals *AppGlobals) {

   dstPort := ""
   dstMAC := ""
   srcMAC := ""
   srcIP := ""
   dstIP := ""

   for _, layerType := range decodedLayers {

       switch layerType {
           case layers.LayerTypeIPv4:
               srcIP = ip.SrcIP.String()
               dstIP = ip.DstIP.String()
           
           case layers.LayerTypeEthernet:
               srcMAC = eth.SrcMAC.String()
               dstMAC = eth.DstMAC.String()

           case layers.LayerTypeTCP:
               dstPort = fmt.Sprintf("%v",uint16(tcp.DstPort))
       }
    }


   if dstMAC == appGlobals.etherAddr && srcMAC != appGlobals.etherAddr  {
   		i := Incident {
   				OffendingMAC: srcMAC,
				OffendingIP:  srcIP,
				IPAttempt:	  dstIP,
				PortAttempt:  dstPort,
				IncidentTime: ci.Timestamp,
   		}

   		if uint16(tcp.DstPort) < appGlobals.EphemeralStart {
   			appGlobals.alertConfig.currentAlert.Ingest(i, appGlobals.alertConfig.whiteListPorts, appGlobals.alertConfig.whiteListMACs, appGlobals.alertConfig.whiteListMACPortCombos)
   		}
   }
   
}


// Listen in an infinite loop for new packets
func Listen(globals *AppGlobals) error {
	// Array to store which layers were decoded
	decoded := []gopacket.LayerType{}

	// Faster, predefined layer parser that doesn't make copies of the layer slices
	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&eth,
		&ip,
		&tcp,
		&udp,
		&icmp,
		&dns,
		&payload)

	// Infinite loop that reads incoming packets
	for globals.isRunning {
		data, ci, err := globals.sniffer.ReadPacket()
		if err != nil && err.Error() != "Timeout Expired" {
			log.Printf("Error getting packet: %v %s", err, ci)
			continue
		}

		err = parser.DecodeLayers(data, &decoded)
		if err != nil && err.Error() != "Ethernet packet too small" && !strings.HasPrefix(err.Error(), "No decoder for layer type") {
			log.Printf("Error decoding packet: %v", err)
			continue
		}
		if len(decoded) == 0 {
			//log.Print("Packet contained no valid layers")
			continue
		}

		handlePacket(decoded, ci, globals)
		
	}

	return nil
}