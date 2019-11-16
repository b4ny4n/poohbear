package main

import (
	"os"
	"os/signal"
	"syscall"
	"log"
	"flag"
	"time"
)


type AppGlobals struct {
	sniffer   	PcapSniffer
	etherAddr	string
	iface 	  	string
	isRunning 	bool
	alertConfig AlertConfig
	EphemeralStart uint16
}



func main() {


	log.Printf(PoohBanner())

	iface := flag.String("iface", "eth0", "interface to sniff. Defaults to eth0")
	sesEmailConfig := flag.String("email", "", "email address used for alerting")
	sesRegionConfig := flag.String("SES region", "us-west-2", "[OPTIONAL] AWS region for SES service, defaults to us-west-2")
	alertIntervalConfig := flag.String("interval", "10m", "[OPTIONAL] interval for batching alerts together, (eg. 30s, 60m). Defaults to 10m")
	whiteListPortsConfig := flag.String("whitelist-ports", "", "[OPTIONAL] CSV string of ports to never alert on (eg: 22,80,443,8888)")
	whiteListMACsConfig := flag.String("whitelist-macs", "", "[OPTIONAL] CSV string of MAC addresses to never alert on (eg: aa:bb:cc:dd:ee:ff,a2:b2:c2:d2:e2:f2)")
	whiteListMACPortCombosConfig := flag.String("whitelist-macsports", "", "[OPTIONAL] CSV string of MAC address|port combinations to never alert on (eg: aa:bb:cc:dd:ee:ff|8888)")



	flag.Parse()

	// TODO - get these as args
	ai, couldParse := time.ParseDuration(*alertIntervalConfig)
	
	if couldParse != nil{
		log.Fatalf("Could not parse duration: %v\n%v", ai, couldParse)
	}
	

	wlp  := parseWhiteListPorts(whiteListPortsConfig)
	wlm  := parseWhiteListMACs(whiteListMACsConfig)
	wlmp := parseWhiteListMACPortCombos(whiteListMACPortCombosConfig)


	// confirm the configs
	log.Printf("")
	log.Printf("======================================")
	log.Printf("Batch alert duration: %v", ai)
	log.Printf("Using white list of ports: %v", wlp)
	log.Printf("Using white list of MACs: %v", wlm)
	log.Printf("Using white list of MAC|port combinations: %v", wlmp)
	log.Printf("======================================")
	log.Printf("")

	sniffer := &PcapSniffer{}
	
	etherAddr := getMacAddr(*iface)

	if err := sniffer.Open(*iface); err != nil {
		log.Fatal("Failed to open the sniffer: ", err)
	}
	
	// initialize an empty alert
	initialAlert := NewAlert()

	// Construct alerting config from the arguments
	ac := AlertConfig {
		alertInterval: ai,
		whiteListPorts: wlp,
		whiteListMACPortCombos: wlmp,
		whiteListMACs: wlm,
		alertHandler: SesAlertHandler,
		currentAlert: initialAlert,
		previousAlert: nil,
		sesEmail: *sesEmailConfig,
		sesRegion: *sesRegionConfig,

	}



	// Global structures all wired together to run
	globals := AppGlobals {
		sniffer: *sniffer,
		etherAddr: etherAddr,
		isRunning: true,
		alertConfig: ac,
		EphemeralStart: 32768,
	}


	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
	
	go func() {
		<-sigc
		log.Print("Received sigterm/sigint, stopping")
		globals.isRunning = false
	}()

	// start alerting loop async
	go func(appGlobals *AppGlobals) {
		for appGlobals.isRunning {
			time.Sleep(appGlobals.alertConfig.alertInterval)
			log.Printf("Alert Cycling")
			appGlobals.alertConfig.Cycle()
		}

	}(&globals)


	Listen(&globals)



}