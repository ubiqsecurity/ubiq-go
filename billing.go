package ubiq

import (
	"strconv"
	"sync"
	"time"
)

type billingEvent struct {
	Action         string `json:"action"`
	ApiKey         string `json:"api_key"`
	ApiVersion     string `json:"api_version"`
	Count          int    `json:"count"`
	DatasetGroups  string `json:"dataset_groups"`
	Datasets       string `json:"datasets"`
	FirstCallAt    string `json:"first_call_timestamp"`
	KeyNumber      string `json:"key_number"`
	LastCallAt     string `json:"last_call_timestamp"`
	Product        string `json:"product"`
	ProductVersion string `json:"product_version"`
	UserAgent      string `json:"user-agent"`
}

type BillingAction string

const (
	BillingActionEncrypt BillingAction = "encrypt"
	BillingActionDecrypt BillingAction = "decrypt"
)

type billingEventKey struct {
	Action        string
	ApiKey        string
	Datasets      string
	DatasetGroups string
	KeyNumber     string
}

type billingContext struct {
	lock sync.Mutex

	billers int
	events  chan billingEvent
}

var BILLING_CONTEXT billingContext

func billingRoutine(inEvents chan billingEvent) {
	events := make(map[billingEventKey]billingEvent)

	for {
		ev, ok := <-inEvents
		if !ok {
			// channel empty and closed
			break
		}

		ek := billingEventKey{
			Action:        ev.Action,
			ApiKey:        ev.ApiKey,
			Datasets:      ev.Datasets,
			DatasetGroups: ev.DatasetGroups,
			KeyNumber:     ev.KeyNumber,
		}

		if ex, ok := events[ek]; ok {
			ex, ev = ev, ex

			ev.Count += ex.Count
			ev.LastCallAt = ex.LastCallAt
		}
		events[ek] = ev
	}
}

func (self *billingContext) addBiller() {
	self.lock.Lock()
	defer self.lock.Unlock()

	if self.billers == 0 {
		self.events = make(chan billingEvent)
		go billingRoutine(self.events)
	}

	self.billers++
}

func (self *billingContext) remBiller() {
	self.lock.Lock()
	defer self.lock.Unlock()

	self.billers--

	if self.billers < 0 {
		panic("number of billers is negative")
	} else if self.billers == 0 {
		close(self.events)
		// billingRoutine stops automatically
	}
}

func (self *billingContext) addEvent(
	papi, dsname, dsgroup string,
	action BillingAction,
	count, kn int) {
	var now string = time.Now().Format(time.RFC3339)

	self.events <- billingEvent{
		Action:         string(action),
		ApiKey:         papi,
		ApiVersion:     "V3",
		Count:          count,
		DatasetGroups:  dsgroup,
		Datasets:       dsname,
		FirstCallAt:    now,
		KeyNumber:      strconv.Itoa(kn),
		LastCallAt:     now,
		Product:        "ubiq-go",
		ProductVersion: Version,
		UserAgent:      "ubiq-go/" + Version,
	}
}
