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
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"

	"mig.ninja/mig/modules"
	// "github.com/mozilla/libaudit-go"
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
	Parameters params
	Results    modules.Result
}

// parameters structure
//TODO: Decide on parameters
// maybe provided in configuration file ?
type params struct {
	RuleFilePaths []string `json:"rulefilepaths"`
	OutputSocket  []string `json:"outputsocket"`
	InitialStart  bool     `json:"initialStart"`
}

type elements struct {
	Hostname     string              `json:"hostname,omitempty"`
	Addresses    []string            `json:"addresses,omitempty"`
	LookedUpHost map[string][]string `json:"lookeduphost,omitempty"`
	Dummyvar     string              `json:"dummyvar,omitempty"`
}

// What kind of statistics are possible, as singular run is not usual by client ?
type statistics struct {
	StuffFound int64 `json:"stufffound"`
}

// It must return an error if the parameters do not validate.
func (r *run) ValidateParameters() (err error) {

	for _, file := range r.Parameters.RuleFilePaths {
		_, err := os.Stat(file)
		if err != nil {
			return fmt.Errorf("ValidateParameters: RuleFilePaths parameter is a not a valid path.")
		}
	}

	for _, unixSocket := range r.Parameters.OutputSocket {
		err := validateUnixSocket(unixSocket)
		if err != nil {
			return err
		}
	}

	return
}

func validateUnixSocket(val string) error {
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: val, Net: "unix"})
	if err != nil {
		return fmt.Errorf("Invalid Unix socket! Unable to open.")
	}
	l.Close()
	os.Remove(val)
	return nil
}

// The code below provides a base module skeleton that can be reused in all modules.
func (r *run) Run(in io.Reader) (out string) {
	// a good way to handle execution failures is to catch panics and store
	// the panicked error into modules.Results.Errors, marshal that, and output
	// the JSON string back to the caller
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
	go r.doModuleStuff(&out, &moduleDone)
	go modules.WatchForStop(in, &stop)

	select {
	case <-moduleDone:
		return out
	case <-stop:
		panic("stop message received, terminating early")
	}
}

// doModuleStuff is an internal module function that does things specific to the
// module. There is no implementation requirement. It's good practice to have it
// return the JSON string Run() expects to return. We also make it return a boolean
// in the `moduleDone` channel to do flow control in Run().
func (r *run) doModuleStuff(out *string, moduleDone *chan bool) error {
	var (
		el    elements
		stats statistics
	)
	el.LookedUpHost = make(map[string][]string)

	// ---
	// From here on, we would normally do something useful, like:

	stats.StuffFound = 0 // count for stuff

	// grab the hostname of the endpoint
	// if r.Parameters.GetHostname {
	// 	hostname, err := os.Hostname()
	// 	if err != nil {
	// 		panic(err)
	// 	}
	el.Hostname = "dummy"
	for _, name := range r.Parameters.RuleFilePaths {
		el.Dummyvar += name
	}
	stats.StuffFound++
	// }

	// grab the local ip addresses
	// if r.Parameters.GetAddresses {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		panic(err)
	}
	for _, addr := range addresses {
		if addr.String() == "127.0.0.1/8" || addr.String() == "::1/128" {
			continue
		}
		el.Addresses = append(el.Addresses, addr.String())
		stats.StuffFound++
	}
	// }

	// look up a host
	// for _, host := range r.Parameters.LookupHost {
	addrs, err := net.LookupHost("www.google.com")
	if err != nil {
		panic(err)
	}
	el.LookedUpHost["www.google.com"] = addrs
	// }

	// marshal the results into a json string
	*out = r.buildResults(el, stats)
	*moduleDone <- true
	return nil
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

// PrintResults() is an *optional* method that returns results in a human-readable format.
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
	for _, addr := range el.Addresses {
		prints = append(prints, fmt.Sprintf("address is %s", addr))
	}
	for host, addrs := range el.LookedUpHost {
		for _, addr := range addrs {
			prints = append(prints, fmt.Sprintf("lookedup host %s has IP %s", host, addr))
		}
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
