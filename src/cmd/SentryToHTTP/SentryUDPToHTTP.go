package main

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	userAgent        = "raven-go/1.0"
	timestampFormat  = `"2006-01-02T15:04:05"`
	timestampFormatZ = `"2006-01-02T15:04:05Z"` // Try the older version as well
)

// Timestamp is our override so we can provide marshalling
type Timestamp time.Time

// MarshalJSON allows time to be marshalled into JSON
func (timestamp Timestamp) MarshalJSON() ([]byte, error) {
	return []byte(time.Time(timestamp).UTC().Format(timestampFormat)), nil
}

// UnmarshalJSON allows time to be unmarshalled from JSON
func (timestamp *Timestamp) UnmarshalJSON(data []byte) error {
	t, err := time.Parse(timestampFormat, string(data))
	if err != nil {
		t, err = time.Parse(timestampFormatZ, string(data))
		if err != nil {
			return err
		}
	}

	*timestamp = Timestamp(t)
	return nil
}

// Severity is so we can provide some consts
type Severity string

// http://docs.python.org/2/howto/logging.html#logging-levels
const (
	DEBUG   = Severity("debug")
	INFO    = Severity("info")
	WARNING = Severity("warning")
	ERROR   = Severity("error")
	FATAL   = Severity("fatal")
)

// An Interface is a Sentry interface that will be serialized as JSON.
// It must implement json.Marshaler or use json struct tags.
type Interface interface {
	// The Sentry class name. Example: sentry.interfaces.Stacktrace
	Class() string
}

type Tag struct {
	Key   string
	Value string
}

type Tags []Tag

func (tag *Tag) MarshalJSON() ([]byte, error) {
	return json.Marshal([2]string{tag.Key, tag.Value})
}

func (t *Tag) UnmarshalJSON(data []byte) error {
	var tag [2]string
	if err := json.Unmarshal(data, &tag); err != nil {
		return err
	}
	*t = Tag{tag[0], tag[1]}
	return nil
}

func (t *Tags) UnmarshalJSON(data []byte) error {
	var tags []Tag

	switch data[0] {
	case '[':
		// Unmarshal into []Tag
		if err := json.Unmarshal(data, &tags); err != nil {
			return err
		}
	case '{':
		// Unmarshal into map[string]string
		tagMap := make(map[string]string)
		if err := json.Unmarshal(data, &tagMap); err != nil {
			return err
		}

		// Convert to []Tag
		for k, v := range tagMap {
			tags = append(tags, Tag{k, v})
		}
	default:
		return fmt.Errorf("Tags Unmarshal failed!")
	}

	*t = tags
	return nil
}

//Packet is the JSON packet that's base64 encoded and Zlibed by sentry clients
type Packet struct {
	// Required
	Message string `json:"message"`

	// Required, set automatically by Client.Send/Report via Packet.Init if blank
	EventID   string    `json:"event_id"`
	Project   string    `json:"project"`
	Timestamp Timestamp `json:"timestamp"`
	Level     int       `json:"level"`
	Logger    string    `json:"logger"`

	// Optional
	Platform    string                 `json:"platform,omitempty"`
	Culprit     string                 `json:"culprit,omitempty"`
	ServerName  string                 `json:"server_name,omitempty"`
	Release     string                 `json:"release,omitempty"`
	Tags        Tags                   `json:"tags,omitempty"`
	Modules     map[string]string      `json:"modules,omitempty"`
	Fingerprint []string               `json:"fingerprint,omitempty"`
	Extra       map[string]interface{} `json:"extra,omitempty"`

	Interfaces []Interface `json:"-"`
}

// Need to reformat and post to
func decodeMessageAndPOST(data []byte) {
	stringifiedData := string(data)
	postedData := strings.Split(stringifiedData, "\n")
	if len(postedData) != 3 {
		log.Printf("decodeMessageAndPOST:: Expected 3 lines, got %v", len(postedData))
		return
	}

	// Get username and password
	header := strings.Split(postedData[0], ", ")

	pubKey := ""
	secKey := ""

	for _, val := range header {
		switch {
		case strings.Contains(val, "sentry_key="):
			pubKey = val[strings.Index(val, "=")+1:]
		case strings.Contains(val, "sentry_secret="):
			secKey = val[strings.Index(val, "=")+1:]
		}
	}

	// Sentry sentry_timestamp=1466488750.79, sentry_client=raven-python/5.1.1, sentry_version=5, sentry_key=pubkey, sentry_secret=secret
	// '{"project": "1", "sentry.interfaces.Message": {"message": "Shitballs", "params": []}, "server_name": "syd-nglynn-d", "extra": {"sys.argv": ["\'\'"]}, "event_id": "a6d60e1188b9419687d30b8523aa2539", "timestamp": "2016-06-21T05:32:10Z", "level": 40, "modules": {}, "time_spent": null, "platform": "python", "message": "Shitballs", "tags": {}}'

	// Try and get our data - it's base64 encoded :(
	data, err := base64.StdEncoding.DecodeString(postedData[2])
	if err != nil {
		log.Printf("Couldn't decode string: %v", err)
		return
	}

	// Decompress
	zlibReader := bytes.NewReader(data)
	w, err := zlib.NewReader(zlibReader)
	if err != nil {
		log.Printf("Didn't get zlib header: %v", err)
		return
	}

	envData := bytes.NewBuffer([]byte{})
	_, err = io.Copy(envData, w)
	if err != nil {
		log.Printf("Didn't get zlib data: %v", err)
		return
	}
	w.Close()

	var p Packet

	err = json.Unmarshal(envData.Bytes(), &p)
	if err != nil {
		log.Printf("Didn't get JSON: %v", err)
		return
	}
	// Send the packet on
	send(&p, pubKey, secKey)
}

func send(packet *Packet, publicKey, secretKey string) error {
	//log.Println("Packet:", packet)
	url := fmt.Sprintf("http://localhost:9000/api/%s/store/", packet.Project)
	authHeader := fmt.Sprintf("Sentry sentry_version=5, sentry_key=%s, sentry_secret=%s", publicKey, secretKey)
	//log.Println("Header:", authHeader)

	body, contentType := serializedPacket(packet)
	req, _ := http.NewRequest("POST", url, body)
	req.Header.Set("X-Sentry-Auth", authHeader)
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", contentType)

	var netClient = &http.Client{
		Timeout: time.Second * 10, // Set a timeout
	}

	res, err := netClient.Do(req)
	if err != nil {
		log.Println(err)
		return err
	}
	io.Copy(ioutil.Discard, res.Body)
	res.Body.Close()
	if res.StatusCode != 200 {
		log.Println("Attempted send with authHeader:", authHeader, fmt.Errorf("| raven: got http status %d", res.StatusCode))
		return fmt.Errorf("raven: got http status %d", res.StatusCode)
	}
	return nil
}

// JSON ify Packets
func (packet *Packet) JSON() []byte {
	packetJSON, _ := json.Marshal(packet)

	interfaces := make(map[string]Interface, len(packet.Interfaces))
	for _, inter := range packet.Interfaces {
		if inter != nil {
			interfaces[inter.Class()] = inter
		}
	}

	if len(interfaces) > 0 {
		interfaceJSON, _ := json.Marshal(interfaces)
		packetJSON[len(packetJSON)-1] = ','
		packetJSON = append(packetJSON, interfaceJSON[1:]...)
	}

	return packetJSON
}

func serializedPacket(packet *Packet) (r io.Reader, contentType string) {
	packetJSON := packet.JSON()

	// Only deflate/base64 the packet if it is bigger than 1KB, as there is
	// overhead.
	if len(packetJSON) > 1000 {
		buf := &bytes.Buffer{}
		b64 := base64.NewEncoder(base64.StdEncoding, buf)
		deflate, _ := zlib.NewWriterLevel(b64, zlib.BestCompression)
		deflate.Write(packetJSON)
		deflate.Close()
		b64.Close()
		return buf, "application/octet-stream"
	}
	return bytes.NewReader(packetJSON), "application/json"
}

func main() {
	/* Bind UDP */
	ServerAddr, err := net.ResolveUDPAddr("udp", ":9002")
	if err != nil {
		log.Fatalln("Error: ", err)
	}

	/* Now listen at selected port */
	ServerConn, err := net.ListenUDP("udp", ServerAddr)
	if err != nil {
		log.Fatalln("Error: ", err)
	}
	defer ServerConn.Close()

	// Make a large enough buffer to handle the practical limit of a UDP packet
	buf := make([]byte, 65535)

	for {
		n, addr, err := ServerConn.ReadFromUDP(buf)
		if err != nil {
			fmt.Println("Failed during ReadFromUDP: ", err)
			continue
		}
		log.Printf("Received Sentry message of %v bytes from %v", n, addr)
		go decodeMessageAndPOST(buf[0:n])
	}
}
