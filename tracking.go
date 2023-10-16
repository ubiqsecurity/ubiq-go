package ubiq

import (
	"bytes"
	"encoding/json"
	"strconv"
	"time"
)

//
// tracking events are sent by the encryption/decryption code
// via the AddEvent function. these events are forwarded to a
// goroutine, running in the background, that stores up the
// events until a minimum number has been gathered or a timeout
// occurs, at which point they are sent to the server.
//
// if a duplicate event occurs, the counter in the currently
// stored event is incremented.
//

//
// the information about a particular event. this structure
// is stored locally until sent to the server and also serves
// as the structure for the message sent to the server via
// the json annotations
//
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

//
// the message sent to the server is an array of
// events under the "usage" name/label
//
type trackingEventMessage struct {
	Usage []*trackingEvent `json:"usage"`
}

type trackingAction string

const (
	trackingActionEncrypt trackingAction = "encrypt"
	trackingActionDecrypt trackingAction = "decrypt"
)

//
// key used to look up locally stored events
// for matching purposes
//
type trackingEventKey struct {
	Action        string
	ApiKey        string
	Datasets      string
	DatasetGroups string
	KeyNumber     string
}

//
// the trackingContext contains the communication channel(s)
// between the code generating tracking events and the background
// goroutine sending events to the server.
//
type trackingContext struct {
	//
	// only the goroutine uses the client
	//
	client httpClient
	host   string

	//
	// tracking events are sent to the
	// background routine via this channel
	//
	events chan *trackingEvent
	//
	// this channel is only used by the background
	// routine to signal completion/exit
	//
	done   chan struct{}
}

func newTrackingContext(client httpClient, host string) trackingContext {
	ctx := trackingContext{
		client: client,
		host:   host,
		events: make(chan *trackingEvent),
		done:   make(chan struct{}),
	}

	go trackingRoutine(ctx, 5, 2*time.Second)
	return ctx
}

//
// serialize the map and send that serialization to the
// designated host via the supplied client. the map is
// cleared by this function
//
func sendTrackingEvents(
	client *httpClient, host string,
	events *map[trackingEventKey]*trackingEvent) {
	if len(*events) > 0 {
		var msg trackingEventMessage
		msg.Usage = make([]*trackingEvent, len(*events))

		// convert the map to a list
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

		// clear the map
		*events = make(map[trackingEventKey]*trackingEvent)
	}
}

//
// the background routine that periodically sends captured
// events to the server. events are sent when a minimum of
// @minCount has been stored or @maxDelay time has passed
// since the last sent update
//
func trackingRoutine(ctx trackingContext,
	minCount int, maxDelay time.Duration) {
	var ok bool = true

	delay := time.NewTimer(maxDelay)
	events := make(map[trackingEventKey]*trackingEvent)

	for ok {
		var expired bool = false
		var ev *trackingEvent

		// wait for either an event to arrive or
		// for the timeout to occur
		select {
		case <-delay.C:
			expired = true
		case ev, ok = <-ctx.events:
			if ok {
				//
				// look up the identifying information
				// for the new event. if the new event
				// matches an existing one, simply update
				// the existing one. otherwise, insert
				// the new one
				//

				ek := trackingEventKey{
					Action:        ev.Action,
					ApiKey:        ev.ApiKey,
					Datasets:      ev.Datasets,
					DatasetGroups: ev.DatasetGroups,
					KeyNumber:     ev.KeyNumber,
				}

				if ex, found := events[ek]; found {
					ex.Count += ev.Count
					ex.LastCallAt = ev.LastCallAt
				} else {
					events[ek] = ev
				}
			}
		}

		// if the minimum number of events has been gathered
		// or the timer has expired, then send the events
		if len(events) >= minCount || expired {
			sendTrackingEvents(&ctx.client, ctx.host, &events)

			// .Reset() shouldn't be called unless the
			// timer is stopped and its channel is empty
			if !expired && !delay.Stop() {
				// timer already expired,
				// drain the channel
				<-delay.C
			}
			delay.Reset(maxDelay)
		}
	}

	// stop the timer; we don't care about the channel
	// since the object is going away anyway
	delay.Stop()
	sendTrackingEvents(&ctx.client, ctx.host, &events)
	// signal that the routine is exiting
	close(ctx.done)
}

func (self *trackingContext) AddEvent(
	papi, dsname, dsgroup string,
	action trackingAction,
	count, kn int) {
	var now string = time.Now().Format(time.RFC3339)

	//
	// note that we send a pointer to the event.
	// this saves several copies of the data, and
	// this pointer will end up in the map used
	// by the background routine
	//
	self.events <- &trackingEvent{
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
	// tell the background routine to exit
	close(self.events)
	// wait for the background routine to exit
	<-self.done
}
