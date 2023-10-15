package ubiq

import (
	"bytes"
	"encoding/json"
	"strconv"
	"time"
)

type trackingEvent struct {
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

type trackingEventMessage struct {
	Usage []trackingEvent `json:"usage"`
}

type TrackingAction string

const (
	TrackingActionEncrypt TrackingAction = "encrypt"
	TrackingActionDecrypt TrackingAction = "decrypt"
)

type trackingEventKey struct {
	Action        string
	ApiKey        string
	Datasets      string
	DatasetGroups string
	KeyNumber     string
}

type trackingContext struct {
	client httpClient
	host   string

	events chan trackingEvent
}

func newTrackingContext(client httpClient, host string) trackingContext {
	ctx := trackingContext{
		client: client,
		host:   host,
		events: make(chan trackingEvent),
	}

	go trackingRoutine(ctx, 5, 2*time.Second)
	return ctx
}

func sendTrackingEvents(
	client *httpClient, host string,
	events *map[trackingEventKey]trackingEvent) {
	if len(*events) > 0 {
		var msg trackingEventMessage
		msg.Usage = make([]trackingEvent, len(*events))

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

		*events = make(map[trackingEventKey]trackingEvent)
	}
}

func trackingRoutine(ctx trackingContext,
	minCount int, maxDelay time.Duration) {
	var ok bool = true

	delay := time.NewTimer(maxDelay)
	events := make(map[trackingEventKey]trackingEvent)

	for ok {
		var expired bool = false
		var ev trackingEvent

		select {
		case <-delay.C:
			expired = true
		case ev, ok = <-ctx.events:
			if ok {
				ek := trackingEventKey{
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
			sendTrackingEvents(&ctx.client, ctx.host, &events)

			if !expired && !delay.Stop() {
				// timer already expired,
				// drain the channel
				<-delay.C
			}
			delay.Reset(maxDelay)
		}
	}

	delay.Stop()
	sendTrackingEvents(&ctx.client, ctx.host, &events)
}

func (self *trackingContext) AddEvent(
	papi, dsname, dsgroup string,
	action TrackingAction,
	count, kn int) {
	var now string = time.Now().Format(time.RFC3339)

	self.events <- trackingEvent{
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

func (self *trackingContext) Close() {
	close(self.events)
}
