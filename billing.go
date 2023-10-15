package ubiq

import (
	"bytes"
	"encoding/json"
	"strconv"
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

type billingEventMessage struct {
	Usage []billingEvent `json:"usage"`
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
	client httpClient
	host   string

	events chan billingEvent
}

func newBillingContext(client httpClient, host string) billingContext {
	ctx := billingContext{
		client: client,
		host:   host,
		events: make(chan billingEvent),
	}

	go billingRoutine(ctx, 5, 2*time.Second)
	return ctx
}

func sendBillingEvents(
	client *httpClient, host string,
	events *map[billingEventKey]billingEvent) {
	if len(*events) > 0 {
		var msg billingEventMessage
		msg.Usage = make([]billingEvent, len(*events))

		i := 0
		for _, v := range *events {
			msg.Usage[i] = v
			i++
		}

		raw, _ := json.Marshal(msg)
		client.Post(
			host+"/api/v3/tracking/events",
			"application/json",
			bytes.NewReader(raw))

		*events = make(map[billingEventKey]billingEvent)
	}
}

func billingRoutine(ctx billingContext,
	minCount int, maxDelay time.Duration) {
	var ok bool = true

	delay := time.NewTimer(maxDelay)
	events := make(map[billingEventKey]billingEvent)

	for ok {
		var expired bool = false
		var ev billingEvent

		select {
		case <-delay.C:
			expired = true
		case ev, ok = <-ctx.events:
			if ok {
				ek := billingEventKey{
					Action:        ev.Action,
					ApiKey:        ev.ApiKey,
					Datasets:      ev.Datasets,
					DatasetGroups: ev.DatasetGroups,
					KeyNumber:     ev.KeyNumber,
				}

				if ex, found := events[ek]; found {
					ex, ev = ev, ex

					ev.Count += ex.Count
					ev.LastCallAt = ex.LastCallAt
				}
				events[ek] = ev
			}
		}

		if len(events) >= minCount || expired {
			sendBillingEvents(&ctx.client, ctx.host, &events)

			if !expired && !delay.Stop() {
				// timer already expired,
				// drain the channel
				<-delay.C
			}
			delay.Reset(maxDelay)
		}
	}

	delay.Stop()
	sendBillingEvents(&ctx.client, ctx.host, &events)
}

func (self *billingContext) AddEvent(
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

func (self *billingContext) Close() {
	close(self.events)
}
