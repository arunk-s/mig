// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// Contributor: Arun Sori arunsori94@gmail.com

// audit is a module that setup rules in audit-framwork in
// linux kernel and retrieves the audit-events emitted from
// the kernel and correlate them to form single event messages.
// Then it forwards those event messages to a UNIX port.

package audit /* import "mig.ninja/mig/modules/audit" */

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"github.com/mozilla/libaudit-go"
	"mig.ninja/mig/modules"
)

type module struct {
}

func (m *module) NewRun() modules.Runner {
	return new(run)
}

func init() {
	modules.Register("audit", new(module))
}

type run struct {
	Parameters    params
	Results       modules.Result
	netlinkSocket *netlinkAudit.NetlinkConnection
}

// parameters structure
type params struct {
	RuleFilePath  string   `json:"rulefilepath"`
	OutputSockets []string `json:"outputsockets"`
}

type elements struct {
	Hostname string `json:"hostname,omitempty"`
}

// What kind of statistics are possible, as singular run is not usual by client ?
type statistics struct {
	StuffFound int64 `json:"stufffound"`
}

// Validates rules file by doing a stat on the file to make sure it exists
func (r *run) ValidateParameters() (err error) {

	_, err = os.Stat(r.Parameters.RuleFilePath)
	if err != nil {
		return fmt.Errorf("ValidateParameters: RuleFilePath parameter is a not a valid path.")
	}
	if len(r.Parameters.OutputSockets) == 0 {
		return fmt.Errorf("ValidateParameters: OutputSockets parameter cannot be omitted.")
	}
	for _, unixSocket := range r.Parameters.OutputSockets {
		err := validateUnixSocket(unixSocket)
		if err != nil {
			return err
		}
	}

	return
}

// validates the unix socket by immediately opening the socket provided and later close it
func validateUnixSocket(val string) error {
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: val, Net: "unix"})
	if err != nil {
		return fmt.Errorf("Invalid Unix socket! Unable to open.")
	}
	l.Close()
	os.Remove(val)
	return nil
}

// Execute the persistent Module and blocks here until a kill signal is received or
// module decided to die. Use stdin and stdout for communication with the agent
// keep sending out heartbeats to stdout
// keep looking stdin for config changes, status requests, kill signal
func (r *run) Run(in io.Reader) (out string) {
	defer func() {
		if e := recover(); e != nil {
			r.Results.Errors = append(r.Results.Errors, fmt.Sprintf("%v", e))
			r.Results.Success = false
			buf, _ := json.Marshal(r.Results)
			out = string(buf[:])
		}
	}()

	// read module parameters from stdin
	err := modules.ReadInputParameters(in, &r.Parameters)
	if err != nil {
		panic(err)
	}
	// verify that the parameters we received are valid
	err = r.ValidateParameters()
	if err != nil {
		panic(err)
	}

	// start a goroutine that does some work and another one that looks
	// for an early stop signal
	moduleDone := make(chan bool)
	stop := make(chan bool)
	go r.runAudit(&out, &moduleDone, &stop)
	go r.watchForSignals(in, &stop)

	select {
	case <-moduleDone:
		return out
	case <-stop:
		panic("stop message received, terminating early")
	}
}

//continously watch stdin for stop signals, config messages
//when one stop message is received, `true`` is sent to a boolean channel
func (r *run) watchForSignals(in io.Reader, stopChan *chan bool) error {
	for {
		msg, err := modules.ReadInput(in)
		if err != nil {
			return err
		}
		if msg.Class == modules.MsgClassStop {
			*stopChan <- true
			return nil
		} else if msg.Class == modules.MsgClassConfig {
			//read config parameters
			err := modules.ReadInputParameters(in, &r.Parameters)
			if err != nil {
				panic(err)
			}
			err = r.ValidateParameters()
			if err != nil {
				panic(err)
			}
			// set config params by reading rules file
			// r.netlinkSocket should be opened by now
			r.setConfigParams()
		} else if msg.Class == modules.MsgClassStatus {
			// more parameters can be added to status message
			// but would require defining a struct that is same
			// across agents and persistent modules
			statusString := "audit " + time.Now().UTC().Format(time.UnixDate)
			err = sendStatusMessage(statusString)
			if err != nil {
				return err
			}
		}
	}
}

func (r *run) runAudit(out *string, moduleDone, stop *chan bool) (err error) {
	var (
		el    elements
		stats statistics
	)

	stats.StuffFound = 0 // count for stuff
	el.Hostname = "dummy"
	stats.StuffFound++

	//open a netlink Connection and attach it to the instance of run
	r.netlinkSocket, err = netlinkAudit.NewNetlinkConnection()
	if err != nil {
		panic(err)
	}

	defer r.netlinkSocket.Close()
	err = netlinkAudit.AuditSetEnabled(r.netlinkSocket, 1)
	if err != nil {
		panic(err)
	}

	// Check if Audit is enabled
	//MSG.DONT_WAIT does not work in VM, should remove that?
	status, err := netlinkAudit.AuditIsEnabled(r.netlinkSocket)

	if err == nil && status == 1 {
		err = sendStatusMessage("audit is enabled")
		if err != nil {
			panic(err)
		}
	} else if err == nil && status == 0 {
		return fmt.Errorf("audit cannot be enabled")
	} else {
		panic(err)
	}
	// set audit configuration by reading the rules file
	// rules file should be libaudit specified json only
	err = r.setConfigParams()
	if err != nil {
		panic(err)
	}
	errChan := make(chan error, 1)
	//keep sending heartbeats
	ticker := time.Tick(5 * time.Second)
	go func() {
		for range ticker {
			heartbeatMsg, err := modules.MakeMessage(modules.MsgClassHeartbeat, nil, false)
			if err != nil {
				panic(err)
			}
			heartbeatMsg = append(heartbeatMsg, []byte("\n")...)
			left := len(heartbeatMsg)
			for left > 0 {
				nb, err := os.Stdout.Write(heartbeatMsg)
				if err != nil {
					panic(err)
				}
				left -= nb
				heartbeatMsg = heartbeatMsg[nb:]
			}
		}
	}()
	// setup output medium and provide it to dispatchEvent
	f, err := os.OpenFile("/tmp/jsonlog", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	go dispatchEvent(f)

	netlinkAudit.GetRawAuditMessages(r.netlinkSocket, messageHandler, &errChan, stop)
	// marshal the results into a json string
	*out = r.buildResults(el, stats)
	*moduleDone <- true
	return nil
}

//send status to process stdout
func sendStatusMessage(msg string) (err error) {
	//sends a MessageClass with parameter as a simple string
	statusMsg, err := modules.MakeMessage(modules.MsgClassStatus, msg, false)
	if err != nil {
		panic(err)
	}
	statusMsg = append(statusMsg, []byte("\n")...)
	left := len(statusMsg)
	for left > 0 {
		nb, err := os.Stdout.Write(statusMsg)
		if err != nil {
			panic(err)
		}
		left -= nb
		statusMsg = statusMsg[nb:]
	}
	return
}

// read and set config parameters such as rule files, audit rate limit etc.
func (r *run) setConfigParams() (err error) {
	// currently reading JSON rule file only
	// invoking the tools will require external call to python
	var jsondump []byte
	jsondump, err = ioutil.ReadFile(r.Parameters.RuleFilePath)
	if err != nil {
		panic(err)
	}
	var m interface{}
	err = json.Unmarshal(jsondump, &m)
	if err != nil {
		panic(err)
	}
	rules := m.(map[string]interface{})

	// Set the maximum number of messages
	// that the kernel will send per second
	var i string
	if _, ok := rules["rate"]; ok {
		i = rules["rate"].(string)
	} else {
		i = "600"
	}
	rateLimit, err := strconv.Atoi(i)
	if err != nil {
		panic(err)
	}
	err = netlinkAudit.AuditSetRateLimit(r.netlinkSocket, rateLimit)
	if err != nil {
		panic(err)
	}

	// Set max limit audit message queue
	if _, ok := rules["buffer"]; ok {
		i = rules["buffer"].(string)
	} else {
		i = "420"
	}
	backlogLimit, err := strconv.Atoi(i)
	if err != nil {
		panic(err)
	}
	err = netlinkAudit.AuditSetBacklogLimit(r.netlinkSocket, backlogLimit)
	if err != nil {
		panic(err)
	}

	// Register current pid with audit
	err = netlinkAudit.AuditSetPid(r.netlinkSocket, uint32(syscall.Getpid()))
	if err != nil {
		panic(err)
	}

	//Delete all rules
	if _, ok := rules["delete"]; ok {
		// TODO: MSG_DONWAIT will not work on low resources system (like VM)? Error while receiving rules
		err = netlinkAudit.DeleteAllRules(r.netlinkSocket)
		if err != nil {
			panic(err)
		}
	}

	dir, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	err = netlinkAudit.SetRules(r.netlinkSocket, jsondump, dir)
	if err != nil {
		panic(err)
	}
	return
}

// buffer for holding single event messages
// var eventBuffer = make([]*netlinkAudit.AuditEvent, 5)

var eventBuffer []*netlinkAudit.AuditEvent

// var auditSerial int64
var auditSerial string

func messageHandler(msg string, event *netlinkAudit.AuditEvent, errChan chan error, args ...interface{}) {
	select {
	case err := <-errChan:

		fmt.Printf("audit event error: %v\n", err)
		fmt.Println(msg)
		// fmt.Println(event.Data)
		fmt.Println("xxxxxxx")
	default:
		//write messages to unix socket
		f, err := os.OpenFile("/tmp/log", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
		if err != nil {
			panic(err)
		}
		defer f.Close()
		if _, err = f.WriteString(msg); err != nil {
			panic(err)
		}
		// if the serial of the next message is the same as we got previously
		// we just add it to the buffer
		// otherwise as soon as we get the new serial, we empty the buffer
		// to pack a JSON message and start with the new serial
		if auditSerial == "" {
			auditSerial = event.Serial
			eventBuffer = append(eventBuffer, event)
		} else if auditSerial == event.Serial {
			eventBuffer = append(eventBuffer, event)
		} else {
			// event is finished up
			// process the messages
			fmt.Println(auditSerial)
			// pack JSON
			handleBuffer(&eventBuffer) // should we do this in a separate go-routine (wouldn't make sense as processing of messages shouldn't take much time)
			auditSerial = event.Serial
			eventBuffer = nil
			eventBuffer = append(eventBuffer, event)
		}
	}
}

// CategoryType denotes types of summary filled in JSON msg
type CategoryType string

const (
	CatEXECVE   CategoryType = "execve"
	CatWRITE    CategoryType = "write"
	CatPTRACE   CategoryType = "ptrace"
	CatATTR     CategoryType = "attribute"
	CatAPPARMOR CategoryType = "apparmor"
	CatCHMOD    CategoryType = "chmod"
	CatCHOWN    CategoryType = "chown"
	CatPROMISC  CategoryType = "promiscuous"
	CatTIME     CategoryType = "time"
)

type jsonMsg struct {
	Category    string                 `json:"category"`
	Hostname    string                 `json:"hostname"`
	ProcessID   int                    `json:"processid"`
	Severity    string                 `json:"severity"`
	Summary     string                 `json:"summary"`
	TimeStamp   string                 `json:"timestamp"`
	Details     map[string]interface{} `json:"details"`
	Tags        []string               `json:"tags"`
	ProcessName string                 `json:"processname"`
}

func handleBuffer(bufferPointer *[]*netlinkAudit.AuditEvent) (err error) {
	var (
		msg      jsonMsg
		category CategoryType
		fullCmd  string
		path     string
		haveJSON bool
	)
	buffer := *bufferPointer
	if len(buffer) == 0 {
		return nil
	}
	msg.Hostname = "localhost" //for now
	msg.ProcessID = 0
	msg.ProcessName = "mig-audit"
	msg.Tags = []string{"mig-audit", "0.0.1", "audit"}
	msg.Details = make(map[string]interface{})
	msg.Details["auditserial"] = auditSerial
	// timeStamp := strconv.FormatFloat(buffer[0].Timestamp, 'f', -1, 64)
	// msg.TimeStamp = time.Unix(int64(buffer[0].Timestamp), 0).Format(time.UnixDate)
	// msg.TimeStamp = buffer[0].Timestamp.Format(time.UnixDate)
	// msg.TimeStamp = buffer[0].Timestamp
	timestamp, err := strconv.ParseFloat(buffer[0].Timestamp, 64)
	if err != nil {
		return err
	}
	msg.TimeStamp = time.Unix(int64(timestamp), 0).Format(time.UnixDate)
	for _, event := range buffer {
		// fmt.Println(event.Type)
		switch event.Type {
		case "ANOM_PROMISCUOUS":
			if _, ok := event.Data["dev"]; ok {
				category = CatPROMISC
				haveJSON = true
				msg.Details["dev"] = event.Data["dev"]
				msg.Details["promiscious"] = event.Data["prom"]
				msg.Details["old_promiscious"] = event.Data["old_prom"]
				if _, oK := event.Data["auid"]; oK {
					name, err := user.LookupId(event.Data["auid"])
					if err == nil {
						msg.Details["originaluser"] = name.Username
					}
					msg.Details["auid"] = event.Data["auid"]
				}
				if _, oK := event.Data["uid"]; oK {
					name, err := user.LookupId(event.Data["uid"])
					if err == nil {
						msg.Details["user"] = name.Username
					}
					msg.Details["uid"] = event.Data["uid"]
				}
				msg.Details["gid"] = event.Data["gid"]
				msg.Details["session"] = event.Data["ses"]
			}
		case "AVC":
			if _, ok := event.Data["apparmor"]; ok {
				category = CatAPPARMOR
				haveJSON = true
				msg.Details["aaresult"] = event.Data["apparmor"]
				msg.Summary = event.Data["info"]
				msg.Details["aacoperation"] = event.Data["operation"]
				msg.Details["aaprofile"] = event.Data["profile"]
				msg.Details["aacommand"] = event.Data["comm"]
				if _, oK := event.Data["parent"]; oK {
					name, err := getProcessName(event.Data["parent"])
					if err == nil {
						msg.Details["parentprocess"] = name
					}
				}
				if _, oK := event.Data["pid"]; oK {
					name, err := getProcessName(event.Data["pid"])
					if err == nil {
						msg.Details["processname"] = name
					}
				}
				msg.Details["aaerror"] = event.Data["error"]
				msg.Details["aaname"] = event.Data["name"]
				msg.Details["aasrcname"] = event.Data["srcname"]
				msg.Details["aaflags"] = event.Data["flags"]
			}
		case "EXECVE":
			// fmt.Printf("%v\n", event.Data)
			// fmt.Println(event.Raw)
			argcount := 0
			argc, ok := event.Data["argc"]
			if ok {
				argcount, err = strconv.Atoi(argc)
				if err != nil {
					panic(err)
				}
			}
			for i := 0; i != argcount; i++ {
				cmd, ok := event.Data[fmt.Sprintf("a%d", i)]
				if ok {
					if fullCmd == "" {
						fullCmd += cmd
					} else {
						fullCmd += " " + cmd
					}
				} else {
					continue
				}
			}
			fmt.Printf("%v\n", fullCmd)
			msg.Details["command"] = fullCmd
		case "CWD":
			// fmt.Printf("%v\n", event.Data)
			// fmt.Println(event.Raw)
			cwd, ok := event.Data["cwd"]
			if ok {
				msg.Details["cwd"] = cwd
			}
		case "PATH":
			// fmt.Printf("%v\n", event.Data)
			// fmt.Println(event.Raw)
			path = event.Data["name"]
			msg.Details["path"] = event.Data["name"]
			msg.Details["inode"] = event.Data["inode"]
			msg.Details["dev"] = event.Data["dev"]
			msg.Details["mode"] = event.Data["mode"]
			msg.Details["ouid"] = event.Data["ouid"]
			msg.Details["ogid"] = event.Data["ogid"]
			msg.Details["rdev"] = event.Data["rdev"]
			// same type of messages leads to overwriting of prev ones: fix this case (check "item" ?)
			// type=PATH msg=audit(1467118452.042:37628): item=0 name="/bin/df" inode=258094 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL
			// type=PATH msg=audit(1467118452.042:37628): item=1 name=(null) inode=135770 dev=08:01 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL

		case "SYSCALL":
			// fmt.Printf("%v\n", event.Data)
			// fmt.Println(event.Raw)
			syscallName, ok := event.Data["syscall"]
			if ok {
				// dir, err := os.Getwd()
				// if err != nil {
				// 	panic(err)
				// }
				// syscallName, err := netlinkAudit.AuditSyscallToName(syscall, dir)
				// if err != nil {
				// 	panic(err)
				// }
				msg.Details["processname"] = event.Data["comm"]
				if syscallName == "write" || syscallName == "unlink" || syscallName == "open" || syscallName == "rename" {
					haveJSON = true
					category = CatWRITE
				} else if syscallName == "setxattr" {
					haveJSON = true
					category = CatATTR
				} else if syscallName == "chmod" {
					haveJSON = true
					category = CatCHMOD
				} else if syscallName == "chown" || syscallName == "fchown" {
					haveJSON = true
					category = CatCHOWN
				} else if syscallName == "ptrace" {
					haveJSON = true
					category = CatPTRACE
				} else if syscallName == "execve" {
					haveJSON = true
					category = CatEXECVE
				} else if syscallName == "ioctl" {
					category = CatPROMISC
				} else if syscallName == "adjtimex" {
					category = CatTIME
				} else {
					fmt.Printf("System call %v is not supported\n", syscallName)
				}
				msg.Details["auditkey"] = event.Data["key"]
				if _, ok := event.Data["ppid"]; ok {
					msg.Details["parentprocess"], err = getProcessName(event.Data["ppid"])
					if err != nil {
						// we can't get name process name?
						msg.Details["parentprocess"] = event.Data["ppid"]
					}
				}
				if _, ok := event.Data["auid"]; ok {
					// userName, err := user.LookupId(event.Data["auid"])
					userName, err := user.Lookup(event.Data["auid"])
					if err == nil {
						msg.Details["originaluser"] = userName.Username
						msg.Details["originaluid"] = userName.Uid
					}
				}
				if _, ok := event.Data["uid"]; ok {
					// userName, err := user.LookupId(event.Data["uid"])
					userName, err := user.Lookup(event.Data["auid"])
					if err == nil {
						msg.Details["user"] = userName.Username
						msg.Details["uid"] = userName.Uid
					}
				}
				msg.Details["tty"] = event.Data["tty"]
				msg.Details["process"] = event.Data["exe"]
				msg.Details["ppid"] = event.Data["ppid"]
				msg.Details["pid"] = event.Data["pid"]
				msg.Details["gid"] = event.Data["gid"]
				msg.Details["euid"] = event.Data["euid"]
				msg.Details["suid"] = event.Data["suid"]
				msg.Details["fsuid"] = event.Data["fsuid"]
				msg.Details["egid"] = event.Data["egid"]
				msg.Details["sgid"] = event.Data["sgid"]
				msg.Details["fsgid"] = event.Data["fsgid"]
				msg.Details["session"] = event.Data["ses"]
			} else {
				msg.Details = nil
			}
		default:

		}
	}
	// reason ?
	if !haveJSON {
		msg.Details = nil
		fmt.Println("Not have JSON skipping !!")
		return
	}
	//fill summary
	// skip empty execve messages ?
	if category == CatEXECVE {
		msg.Category = "execve"
		msg.Summary = fmt.Sprintf("Execve %s", fullCmd)

	} else if category == CatWRITE {
		msg.Category = "write"
		msg.Summary = fmt.Sprintf("Write: %s", path)
	} else if category == CatATTR {
		msg.Category = "attribute"
		msg.Summary = fmt.Sprintf("Chmod %s", path)
	} else if category == CatCHOWN {
		msg.Category = "chown"
		msg.Summary = fmt.Sprintf("Chown %s", path)
	} else if category == CatPTRACE {
		msg.Category = "ptrace"
		msg.Summary = fmt.Sprintf("Ptrace")
	} else if category == CatTIME {
		msg.Category = "time"
		msg.Summary = fmt.Sprintf("time has been modified")
	} else if category == CatPROMISC {
		msg.Category = "promiscuous"
		msg.Summary = fmt.Sprintf("Promisc: Interface %s set promiscous %s", msg.Details["dev"], msg.Details["au"])
	}
	msgBytes, err := json.Marshal(msg)
	fmt.Printf("%v\n", string(msgBytes))

	// sending message via a go-routine by writing to a buffered channel
	select {
	case jsonBuffChan <- &msg:
		fmt.Println("sent message", msg)
	default:
		fmt.Println("skipping message", msg)
	}

	return
}

func getProcessName(pid string) (name string, err error) {
	processPath := fmt.Sprintf("/proc/%s/status", pid)
	fd, err := os.Open(processPath)
	if err != nil {
		return "", err
	}
	defer fd.Close()
	reader := bufio.NewReader(fd)
	fmt.Fscanf(reader, "Name: %63s", &name)

	return
}

var (
	maxQueueSize = 8192
	// buffered chan for holding json messages
	jsonBuffChan = make(chan *jsonMsg, 500)
)

// abstract function that writes to whatever output provided(socket, file etc.)
// reads messages from buffered chan jsonBuffChan & invoked in a separate go-routine
func dispatchEvent(output io.Writer) {
	for {
		select {
		case msg := <-jsonBuffChan:
			fmt.Println("Writing")
			msgBytes, err := json.Marshal(*msg)
			if err != nil {
				panic(err) // or should I ?
			}
			msgBytes = append(msgBytes, []byte("\n")...)
			left := len(msgBytes)
			for left > 0 {
				nb, err := output.Write(msgBytes)

				if err != nil {
					panic(err)
					// retry to resend the message ?
				}
				left -= nb
				msgBytes = msgBytes[nb:]
			}

		}
	}
}

// buildResults takes the results found by the module, as well as statistics,
// and puts all that into a JSON string. It also takes care of setting the
// success and foundanything flags.
func (r *run) buildResults(el elements, stats statistics) string {
	if len(r.Results.Errors) == 0 {
		r.Results.Success = true
	}
	r.Results.Elements = el
	r.Results.Statistics = stats
	if stats.StuffFound > 0 {
		r.Results.FoundAnything = true
	}
	jsonOutput, err := json.Marshal(r.Results)
	if err != nil {
		panic(err)
	}
	return string(jsonOutput[:])
}

// if matchOnly is set, only results that have at least one match are returned.
// If matchOnly is not set, all results are returned, along with errors and statistics.
func (r *run) PrintResults(result modules.Result, matchOnly bool) (prints []string, err error) {
	var (
		el    elements
		stats statistics
	)
	err = result.GetElements(&el)
	if err != nil {
		panic(err)
	}
	if el.Hostname != "" {
		prints = append(prints, fmt.Sprintf("hostname is %s", el.Hostname))
	}
	if matchOnly {
		return
	}
	for _, e := range result.Errors {
		prints = append(prints, fmt.Sprintf("error: %v", e))
	}
	err = result.GetStatistics(&stats)
	if err != nil {
		panic(err)
	}
	prints = append(prints, fmt.Sprintf("stat: %d stuff found", stats.StuffFound))
	return
}
