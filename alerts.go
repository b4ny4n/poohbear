package main

import (
	"strings"
	"time"
	"fmt"
	"log"
)


type Incident struct {
	OffendingMAC string
	OffendingIP	 string
	IPAttempt	 string
	PortAttempt  string
	IncidentTime time.Time
}

func (i *Incident) String() string {
	return fmt.Sprintf("(%v@%v) tried to connect on %v:%v at %v", i.OffendingMAC, i.OffendingIP, i.IPAttempt, i.PortAttempt, i.IncidentTime)
}

type MACPlusPort struct {
	mac string
	port string
}

func NewAlert() *Alert {
	initialAlert := &Alert {}
	incidentHolder := make([]Incident, 0)
	incidentTracker := make(map[MACPlusPort]bool)
	initialAlert.Incidents = &incidentHolder
	initialAlert.IncidentTracker = &incidentTracker

	return initialAlert
}

type Alert struct {
	Incidents *[]Incident
	IncidentTracker *map[MACPlusPort]bool
}

type AlertHandler func(alert *Alert, ac AlertConfig)

// SES Implementation
func SesAlertHandler(alert *Alert, ac AlertConfig) {
	thisAlertMessage := alert.GetAsHTML()
	// log.Printf("ALERTING: %v", len(*alert.Incidents))
	SendEmail(thisAlertMessage, ac)
}

type AlertConfig struct {
	alertInterval 			time.Duration
	whiteListPorts 			map[string]bool
	whiteListMACPortCombos 	map[string]map[string]bool
	whiteListMACs           map[string]bool
	alertHandler            AlertHandler
	currentAlert			*Alert
	previousAlert			*Alert
	sesEmail    string
	sesRegion   string

}

type ConsolidatedIncident struct {
	batchedIncidents map[string][]Incident
}


func (a *Alert) IsNull() bool {
	return len(*a.Incidents) == 0
}

func (ac *AlertConfig) Cycle() {

	diffedIncidents := ac.currentAlert.DiffAlerts(ac.previousAlert)
	
	diffedAlert := Alert{
		Incidents: &diffedIncidents,	
	}
	
	if len(diffedIncidents) > 0 {
		ac.alertHandler(&diffedAlert, *ac)
		ac.previousAlert = ac.currentAlert
	}

	ac.currentAlert = NewAlert()
}

func (a *Alert) GetAsHTML() string {
	consolidated := a.GetConsolidated()
	sb := strings.Builder{}
	for i := range consolidated.batchedIncidents {
		sb.WriteString(fmt.Sprintf("<p><b>%v</b><br>", i))
		for _, v := range consolidated.batchedIncidents[i] {
			sb.WriteString(fmt.Sprintf("%v<br>", v.String()))
		}
		sb.WriteString("</p>")
	}
	return sb.String()
}

func (a *Alert) GetConsolidated() ConsolidatedIncident {
	aMap := make(map[string][]Incident)
	for _, i := range *a.Incidents {
		aMap[i.OffendingMAC] = append(aMap[i.OffendingMAC], i)
	}
	return ConsolidatedIncident{batchedIncidents: aMap}
}

func (a *Alert) GetAsMessage() string {
	aMap :=a.GetConsolidated().batchedIncidents

	sb := strings.Builder{}
	for k := range aMap {
		sb.WriteString(fmt.Sprintf("=========\n%v\n=========\n", k))
		for _, v := range aMap[k] {
			sb.WriteString(fmt.Sprintf("%v\n", v.String()))
		}
	}

	return sb.String()
}

func (a *Alert) DiffAlerts(lastAlert *Alert) []Incident {

	novelIncidents := make([]Incident,0)
	if lastAlert == nil {
		return *a.Incidents
	}
	
	// build a map from the previous alert 
	lastMap := make(map[MACPlusPort]bool)
	for _, i := range *lastAlert.Incidents {
		lastMap[MACPlusPort{i.OffendingMAC, i.PortAttempt}] = true
	}

	// return incidents which weren't alerted on in the previous iteration cycle
	
	for _, i := range *a.Incidents {
		_, ok := lastMap[MACPlusPort{i.OffendingMAC, i.PortAttempt}] 

		if !ok {
			novelIncidents = append(novelIncidents, i)
		}
	}
	log.Printf("Found %v novel incidents", len(novelIncidents))
	return novelIncidents
}

func (a *Alert) Ingest(i Incident, whiteListPorts map[string]bool, whiteListMACs map[string]bool, whiteListMACPortCombos map[string]map[string]bool ) {

	//mutate with incident if necessary
	_, ok := whiteListPorts[i.PortAttempt] 
	if ok {
		log.Printf("Attempt against a whitelisted port, continuing")
		return
	} else {

	}

	 _, ok = whiteListMACs[i.OffendingMAC] 
	 if ok {
		log.Printf("Attempt came from a whitelisted MAC, continuing")
		return
	}

	 _, okMAC := whiteListMACPortCombos[i.OffendingMAC] 
	 if okMAC { 
	 	 _, okPort := whiteListMACPortCombos[i.OffendingMAC][i.PortAttempt] 
	 	 if okPort {
			log.Printf("Attempt from a whitelisted MAC:port, continuing")
			return
	 	 }
	}

	// ensure we haven't already alerted on this incident before we append to slice
	alertCheck := *a.IncidentTracker
	_, alreadyAlerted := alertCheck[MACPlusPort{i.OffendingMAC, i.PortAttempt}]
	
	if !(alreadyAlerted) {

		newIncidents := append(*a.Incidents, i)
		a.Incidents = &newIncidents
		alertCheck[MACPlusPort{i.OffendingMAC, i.PortAttempt}] = true
		log.Printf("Adding incident\n%v\n now @ %v incident(s)", i.String(), len(*a.Incidents))
	} 




}
