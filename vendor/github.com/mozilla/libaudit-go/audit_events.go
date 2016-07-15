package netlinkAudit

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/pkg/errors"
)

type EventCallback func(*AuditEvent, chan error, ...interface{})

type RawEventCallback func(string, chan error, ...interface{})

type AuditEvent struct {
	Serial    string
	Timestamp string
	Type      string
	Data      map[string]string
	Raw       string
}

type record struct {
	syscallNum string
	arch       string
	a0         int
	a1         int
}

// ParseAuditEventRegex takes an audit event message and returns the essentials to form an AuditEvent struct
// regex used in the function should always match for a proper audit event
func ParseAuditEventRegex(str string) (serial string, timestamp string, m map[string]string, err error) {
	re := regexp.MustCompile(`audit\((?P<timestamp>\d+\.\d+):(?P<serial>\d+)\): (.*)$`)
	match := re.FindStringSubmatch(str)

	if len(match) != 4 {
		err = errors.New("Error while parsing audit message : Invalid Message")
		return
	}
	serial = match[2]
	// serial, err = strconv.ParseInt(match[2], 10, 64)
	// if err != nil {
	// 	err = errors.New("Error while parsing audit message : Invalid Message")
	// 	return
	// }
	// s := strings.Split(match[1], ".")
	// if len(s) != 2 {
	// 	err = errors.New("Error while parsing audit message : Invalid Message")
	// 	return
	// }

	// sec, err := strconv.ParseInt(s[0], 10, 64)
	// if err != nil {
	// 	panic(err)
	// }
	// nsec, err := strconv.ParseInt(s[1], 10, 64)
	// if err != nil {
	// 	panic(err)
	// }
	timestamp = match[1]
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

// ParseAuditEvent parses an incoming audit message from kernel and
// returns and AuditEvent. It relies on using simple string parsing techniques.
// idea taken from static int parse_up_record(rnode* r) in ellist.c (libauparse)
// sample messages to be tested against
// audit(1267534395.930:19): user pid=1169 uid=0 auid=4294967295 ses=4294967295 subj=system_u:unconfined_r:unconfined_t msg='avc: denied { read } for request=SELinux:SELinuxGetClientContext comm=X-setest resid=3c00001 restype=<unknown> scontext=unconfined_u:unconfined_r:x_select_paste_t tcontext=unconfined_u:unconfined_r:unconfined_t  tclass=x_resource : exe="/usr/bin/Xorg" sauid=0 hostname=? addr=? terminal=?' [currently failing]
// audit(1464176620.068:1445): auid=4294967295 uid=1000 gid=1000 ses=4294967295 pid=23975 comm="chrome" exe="/opt/google/chrome/chrome" sig=0 arch=c000003e syscall=273 compat=0 ip=0x7f1da6d8b694 code=0x50000
// audit(1464163771.720:20): arch=c000003e syscall=1 success=yes exit=658651 a0=6 a1=7f26862ea010 a2=a0cdb a3=0 items=0 ppid=712 pid=716 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="apparmor_parser" exe="/sbin/apparmor_parser" key=(null)
//audit(1464093935.845:993): pid=4148 uid=0 auid=4294967295 ses=4294967295 msg='op=PAM:setcred acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/18 res=success'
// audit(1226874073.147:96): avc:  denied  { getattr } for  pid=2465 comm="httpd" path="/var/www/html/file1" dev=dm-0 ino=284133 scontext=unconfined_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:samba_share_t:s0 tclass=file
//
// msgType is supposed to be come from the calling function which holds the msg header indicating type of the messages
func ParseAuditEvent(str string, msgType auditConstant) (*AuditEvent, error) {
	var r record
	m := make(map[string]string)
	if strings.HasPrefix(str, "audit(") {
		str = str[6:]
	} else {
		return nil, fmt.Errorf("malformed audit message")
	}
	index := strings.Index(str, ":")
	if index == -1 {
		return nil, fmt.Errorf("malformed audit message")
	}
	// determine timeStamp
	timestamp := str[:index]
	// move further on string, skipping ':'
	str = str[index+1:]
	index = strings.Index(str, ")")
	if index == -1 {
		return nil, fmt.Errorf("malformed audit message")
	}
	serial := str[:index]
	if strings.HasPrefix(str, serial+"): ") {
		str = str[index+3:]
	} else {
		return nil, fmt.Errorf("malformed audit message")
	}

	var nBytes string
	var orig = len(str)
	var n int
	var key string
	var value string
	var av bool
	for n < orig {
		getSpaceSlice(&str, &nBytes, &n)
		var newIndex int
		newIndex = strings.Index(nBytes, "=")
		if newIndex == -1 {
			// check type for special cases of AVC and USER_AVC
			if msgType == AUDIT_AVC || msgType == AUDIT_USER_AVC {
				if nBytes == "avc:" && strings.HasPrefix(str, "avc:") {
					// skip over 'avc:'
					str = str[len(nBytes)+1:]
					av = true
					continue
				}
				if av {
					key = "seresult"
					value = nBytes
					m[key] = value
					av = false
					if len(str) == len(nBytes) {
						break
					} else {
						str = str[len(nBytes)+1:]
					}
					continue
				}
				if strings.HasPrefix(nBytes, "{") {
					key = "seperms"
					str = str[len(nBytes)+1:]
					var v string
					getSpaceSlice(&str, &nBytes, &n)
					for nBytes != "}" {
						if len(v) != 0 {
							v += ","
						}
						v += nBytes
						str = str[len(nBytes)+1:]
						getSpaceSlice(&str, &nBytes, &n)
					}
					value = v
					m[key] = value
					fixPunctuantions(&value)
					if len(str) == len(nBytes) {
						//reached the end of message
						break
					} else {
						str = str[len(nBytes)+1:]
					}
					continue
				} else {
					// we might get values with space
					// add it to prev key
					// skip 'for' in avc message (special case)
					if nBytes == "for" {
						str = str[len(nBytes)+1:]
						continue
					}
					value += " " + nBytes
					fixPunctuantions(&value)
					m[key] = value
				}
			} else {
				// we might get values with space
				// add it to prev key
				value += " " + nBytes
				fixPunctuantions(&value)
				m[key] = value
			}

		} else {
			key = nBytes[:newIndex]
			value = nBytes[newIndex+1:]
			// for cases like msg='
			// we look again for key value pairs
			if strings.HasPrefix(value, "'") && key == "msg" {
				newIndex = strings.Index(value, "=")
				if newIndex == -1 {
					// special case USER_AVC messages, start of: msg='avc:
					if strings.HasPrefix(str, "msg='avc") {
						str = str[5:]
					}
					continue
				}
				key = value[1:newIndex]
				value = value[newIndex+1:]
			}

			fixPunctuantions(&value)
			if key == "arch" {
				// determine machine type
			}
			if key == "a0" {
				val, err := strconv.ParseInt(value, 16, 64)
				if err != nil {
					//return nil, errors.Wrap(err, "parsing a0 failed")
					r.a0 = -1
				} else {
					value = strconv.FormatInt(val, 10)
					r.a0 = int(val)
				}
			}
			if key == "a1" {
				val, err := strconv.ParseInt(value, 16, 64)
				if err != nil {
					// return nil, errors.Wrap(err, "parsing a1 failed")
					r.a1 = -1
				} else {
					value = strconv.FormatInt(val, 10)
					r.a1 = int(val)
				}
			}
			if key == "syscall" {
				r.syscallNum = value
			}
			m[key] = value
		}
		if len(str) == len(nBytes) {
			//reached the end of message
			break
		} else {
			str = str[len(nBytes)+1:]
		}

	}

	for key, value := range m {
		ivalue, err := InterpretField(key, value, msgType, r)
		if err != nil {
			return nil, err
		}
		m[key] = ivalue
	}

	return &AuditEvent{
		Raw:       str,
		Type:      msgType.String()[6:],
		Data:      m,
		Serial:    serial,
		Timestamp: timestamp,
	}, nil

}

// getSpaceSlice checks the index of the next space and put the string upto that space into
// the second string, total number of characters is updated with each call to the function
func getSpaceSlice(str *string, b *string, v *int) {
	// retry:
	index := strings.Index(*str, " ")
	if index != -1 {
		// *b = []byte((*str)[:index])
		if index == 0 {
			// found space on the first location only
			// just forward on the orig string and try again
			*str = (*str)[1:]
			// goto retry (tradeoff discussion goto or functionCall?)
			getSpaceSlice(str, b, v)
		} else {
			*b = (*str)[:index]
			// keep updating total characters processed
			*v += len(*b)
		}
	} else {
		*b = (*str)
		// keep updating total characters processed
		*v += len(*b)
	}
}

func fixPunctuantions(value *string) {
	// Remove trailing punctuation
	l := len(*value)
	if l > 0 && strings.HasSuffix(*value, "'") {
		*value = (*value)[:l-1]
		l--
	}
	if l > 0 && strings.HasSuffix(*value, ",") {
		*value = (*value)[:l-1]
		l--
	}
	if l > 0 && strings.HasSuffix(*value, ")") {
		if *value != "(none)" && *value != "(null)" {
			*value = (*value)[:l-1]
			l--
		}
	}
	if l > 0 && strings.HasSuffix(*value, "\"") {
		*value = (*value)[:l-1]
		l--
	}
	// remove begining quotes
	if l > 0 && strings.HasPrefix(*value, "\"") {
		*value = (*value)[1:]
		l--
	}
}

//NewAuditEvent takes NetlinkMessage passed from the netlink connection
//and parses the data from message to return an AuditEvent struct
func NewAuditEvent(msg NetlinkMessage) (*AuditEvent, error) {
	x, err := ParseAuditEvent(string(msg.Data[:]), auditConstant(msg.Header.Type))
	if err != nil {
		return nil, err
	}
	if (*x).Type == "auditConstant("+strconv.Itoa(int(msg.Header.Type))+")" {
		return nil, errors.New("Unknown Type: " + string(msg.Header.Type))
	}

	return x, nil
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
							// log.Println("NLMSG ERROR")
							continue
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
						} else {
							continue
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

func GetRawAuditMessages(s *NetlinkConnection, cb EventCallback, ec *chan error, done *chan bool, args ...interface{}) {
	for {
		select {
		case <-*done:
			return
		default:
			msgs, _ := s.Receive(syscall.NLMSG_HDRLEN+MAX_AUDIT_MESSAGE_LENGTH, 0)
			for _, msg := range msgs {
				if msg.Header.Type == syscall.NLMSG_ERROR {
					err := int32(nativeEndian().Uint32(msg.Data[0:4]))
					if err == 0 {
						//Acknowledgement from kernel
					} else {
						continue
					}
				} else {
					nae, err := NewAuditEvent(msg)
					if err != nil {
						*ec <- err
					}
					cb(nae, *ec, args...)
				}
			}
		}
	}

}
