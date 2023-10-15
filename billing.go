package ubiq

import (
	"sync"
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

type billingContext struct {
	lock sync.Mutex

	billers int
	events  chan billingEvent
}

var BILLING_CONTEXT billingContext

func billingRoutine(events chan billingEvent) {
	for {
		_, ok := <-events
		if !ok {
			// channel empty and closed
			break
		}
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
