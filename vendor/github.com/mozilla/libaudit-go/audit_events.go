package netlinkAudit

import (
	"errors"
	"log"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type EventCallback func(*AuditEvent, chan error, ...interface{})

type RawEventCallback func(string, chan error, ...interface{})

type EventCb func(string, *AuditEvent, chan error, ...interface{})

type AuditEvent struct {
	Serial    int64
	Timestamp time.Time
	Type      string
	Data      map[string]string
	Raw       string
}

/*
func ParseAuditKeyValue(str string) (map[string][string], err error) {
	audit_key_string := map[string]bool{
	}
	re_kv := regexp.MustCompile(`((?:\\.|[^= ]+)*)=("(?:\\.|[^"\\]+)*"|(?:\\.|[^ "\\]+)*)`)
	re_quotedstring := regexp.MustCompile(`".+"`)

	kv := re_kv.FindAllStringSubmatch(str, -1)
	m := make(map[string]string)

	for _, e := range kv {
		key := e[1]
		value := e[2]
		if re_quotedstring.MatchString(value) {
			value = strings.Trim(value, "\"")
		}

		if audit_key_string[key] {
			if re_quotedstring.MatchString(value) == false {
				v, err := hex.DecodeString(value)
				if err == nil {
					m[key] = string(v)
				}
			}
		} else {
			m[key] = value
		}
	}
	return m
}

func ParseAuditEvent(str string) (int, float64, map[string]string, error) {
	// re := regexp.MustCompile(`^audit\((\d+\.\d+):(\d+)\): (.*)$`)
	re := regexp.MustCompile(`audit\((?P<timestamp>\d+\.\d+):(?P<serial>\d+)\): (.*)$`)
	match := re.FindStringSubmatch(str)

	if len(match) != 4 {
		return 0, 0, nil, errors.New("Error while parsing audit message : Invalid Message")
	}

	serial, err := strconv.ParseInt(match[2], 10, 64)
	if err != nil {
		return 0, 0, nil, errors.New("Error while parsing audit message : Invalid Message")
	}

	timestamp, err := strconv.ParseFloat(match[1], 64)
	if err != nil {
		return 0, 0, nil, errors.New("Error while parsing audit message : Invalid Message")
	}

	data := ParseAuditKeyValue(match[3])

	return int(serial), timestamp, data, nil
}
*/

// ParseAuditEvent takes an audit event message and returns the essentials to form an AuditEvent struct
// regex used in the function should always match for a proper audit event
func ParseAuditEvent(str string) (serial int64, timestamp time.Time, m map[string]string, err error) {
	re := regexp.MustCompile(`audit\((?P<timestamp>\d+\.\d+):(?P<serial>\d+)\): (.*)$`)
	match := re.FindStringSubmatch(str)

	if len(match) != 4 {
		err = errors.New("Error while parsing audit message : Invalid Message")
		return
	}

	serial, err = strconv.ParseInt(match[2], 10, 64)
	if err != nil {
		err = errors.New("Error while parsing audit message : Invalid Message")
		return
	}
	s := strings.Split(match[1], ".")
	if len(s) != 2 {
		err = errors.New("Error while parsing audit message : Invalid Message")
		return
	}

	sec, err := strconv.ParseInt(s[0], 10, 64)
	if err != nil {
		panic(err)
	}
	nsec, err := strconv.ParseInt(s[1], 10, 64)
	if err != nil {
		panic(err)
	}
	timestamp = time.Unix(sec, nsec)
	data := ParseAuditKeyValue(match[3])
	return serial, timestamp, data, nil
}

// ParseAuditKeyValue takes the field=value part of audit message and returns a map of fields with values
// Important: Regex is to be tested against vast type of audit messages
// Unsupported:
// type=CRED_REFR msg=audit(1464093935.845:993): pid=4148 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:setcred acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/18 res=success'
// type=AVC msg=audit(1226874073.147:96): avc:  denied  { getattr } for  pid=2465 comm="httpd" path="/var/www/html/file1" dev=dm-0 ino=284133 scontext=unconfined_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:samba_share_t:s0 tclass=file
// 										^	this part is missed			 ^
// lua decoder works with all kinds but similar regex capability is unavailable in Go so it should be fixed in Go way
func ParseAuditKeyValue(str string) map[string]string {
	fields := regexp.MustCompile(`(?P<fieldname>[A-Za-z0-9_-]+)=(?P<fieldvalue>"(?:[^'"\\]+)*"|(?:[^ '"\\]+)*)|'(?:[^"'\\]+)*'`)
	matches := fields.FindAllStringSubmatch(str, -1)
	m := make(map[string]string)
	for _, e := range matches {
		key := e[1]
		value := e[2]
		reQuotedstring := regexp.MustCompile(`".+"`)
		if reQuotedstring.MatchString(value) {
			value = strings.Trim(value, "\"")
		}
		m[key] = value
	}

	return m

}

func NewAuditEvent(msg NetlinkMessage) (*AuditEvent, error) {
	serial, timestamp, data, err := ParseAuditEvent(string(msg.Data[:]))
	if err != nil {
		return nil, err
	}

	raw := string(msg.Data[:])
	aetype := auditConstant(msg.Header.Type).String()[6:]
	if aetype == "auditConstant("+strconv.Itoa(int(msg.Header.Type))+")" {
		return nil, errors.New("Unknown Type: " + string(msg.Header.Type))
	}

	ae := &AuditEvent{
		Serial:    serial,
		Timestamp: timestamp,
		Type:      aetype,
		Data:      data,
		Raw:       raw,
	}
	return ae, nil
}

func GetAuditEvents(s *NetlinkConnection, cb EventCallback, ec chan error, args ...interface{}) {
	go func() {
		for {
			select {
			default:
				msgs, _ := s.Receive(syscall.NLMSG_HDRLEN+MAX_AUDIT_MESSAGE_LENGTH, 0)
				for _, msg := range msgs {
					if msg.Header.Type == syscall.NLMSG_ERROR {
						err := int32(nativeEndian().Uint32(msg.Data[0:4]))
						if err == 0 {
							//Note - NLMSG_ERROR can be Acknowledgement from kernel
							//If the first 4 bytes of Data part are zero
						} else {
							log.Println("NLMSG ERROR")
						}
					} else {
						nae, err := NewAuditEvent(msg)
						if err != nil {
							ec <- err
						}
						cb(nae, ec, args...)
					}
				}
			}
		}
	}()
}

func GetRawAuditEvents(s *NetlinkConnection, cb RawEventCallback, ec chan error, args ...interface{}) {
	go func() {
		for {
			select {
			default:
				msgs, _ := s.Receive(syscall.NLMSG_HDRLEN+MAX_AUDIT_MESSAGE_LENGTH, 0)
				for _, msg := range msgs {
					m := ""
					if msg.Header.Type == syscall.NLMSG_ERROR {
						err := int32(nativeEndian().Uint32(msg.Data[0:4]))
						if err == 0 {
							//Acknowledgement from kernel
						}
					} else {
						Type := auditConstant(msg.Header.Type)
						if Type.String() == "auditConstant("+strconv.Itoa(int(msg.Header.Type))+")" {
							ec <- errors.New("Unknown Type: " + string(msg.Header.Type))
						} else {
							m = "type=" + Type.String()[6:] + " msg=" + string(msg.Data[:]) + "\n"
						}
					}
					cb(m, ec, args...)
				}
			}
		}
	}()
}

func GetRawAuditMessages(s *NetlinkConnection, cb EventCb, ec *chan error, done *chan bool, args ...interface{}) {
	for {
		select {
		case <-*done:
			return
		default:
			msgs, _ := s.Receive(syscall.NLMSG_HDRLEN+MAX_AUDIT_MESSAGE_LENGTH, 0)
			for _, msg := range msgs {
				m := ""
				if msg.Header.Type == syscall.NLMSG_ERROR {
					err := int32(nativeEndian().Uint32(msg.Data[0:4]))
					if err == 0 {
						//Acknowledgement from kernel
					} else {
						continue
					}
				} else {
					Type := auditConstant(msg.Header.Type)
					if Type.String() == "auditConstant("+strconv.Itoa(int(msg.Header.Type))+")" {
						*ec <- errors.New("Unknown Type: " + string(msg.Header.Type))
					} else {
						m = "type=" + Type.String()[6:] + " msg=" + string(msg.Data[:]) + "\n"
					}
					nae, err := NewAuditEvent(msg)
					if err != nil {
						*ec <- err
					}
					cb(m, nae, *ec, args...)
				}
			}
		}
	}

}
