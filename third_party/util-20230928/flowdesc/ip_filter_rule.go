package flowdesc

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

const ProtocolNumberAny = 0xfc

// Action - Action of IPFilterRule
type Action string

// Action const
const (
	Permit Action = "permit"
	Deny   Action = "deny"
)

// Direction - direction of IPFilterRule
type Direction string

// Direction const
const (
	In  Direction = "in"
	Out Direction = "out"
)

func flowDescErrorf(format string, a ...interface{}) error {
	msg := fmt.Sprintf(format, a...)
	return fmt.Errorf("flowdesc: %s", msg)
}

type PortRanges []PortRange

// IPFilterRule define RFC 3588 that referd by TS 29.212
type IPFilterRule struct {
	Action   Action
	Dir      Direction
	Proto    uint8      // protocol number
	Src      string     // <address/mask>
	SrcPorts PortRanges // [ports]
	Dst      string     // <address/mask>
	DstPorts PortRanges // [ports]
}

type PortRange struct {
	Start uint16
	End   uint16
}

// NewIPFilterRule returns a new IPFilterRule instance
func NewIPFilterRule() *IPFilterRule {
	r := &IPFilterRule{
		Action:   Permit,
		Dir:      Out,
		Proto:    ProtocolNumberAny,
		Src:      "",
		SrcPorts: []PortRange{},
		Dst:      "",
		DstPorts: []PortRange{},
	}
	return r
}

func (p *PortRange) String() string {
	portRange := ""
	if p == nil {
		return portRange
	}
	if p.Start != p.End {
		// for range port e.g. 2000-5000
		portRange = portRange + fmt.Sprint(p.Start) + "-" + fmt.Sprint(p.End)
	} else {
		portRange = portRange + fmt.Sprint(p.Start)
	}
	return portRange
}

func (ps PortRanges) String() string {
	ports := ""
	if ps == nil {
		return ports
	}
	lastPortIdx := len(ps) - 1
	for i, port := range ps {
		ports += port.String()
		if i != lastPortIdx {
			ports += ","
		}
	}
	return ports
}

// SwapSourceAndDestination swap the src and dst of the IPFilterRule
func (r *IPFilterRule) SwapSrcAndDst() {
	r.Src, r.Dst = r.Dst, r.Src
	r.SrcPorts, r.DstPorts = r.DstPorts, r.SrcPorts
}

// Encode function out put the IPFilterRule from the struct
func Encode(r *IPFilterRule) (string, error) {
	var ipFilterRuleStr []string

	// pre-allocate seven element
	ipFilterRuleStr = make([]string, 0, 9)

	// action
	switch r.Action {
	case Permit:
		ipFilterRuleStr = append(ipFilterRuleStr, "permit")
	case Deny:
		ipFilterRuleStr = append(ipFilterRuleStr, "deny")
	default:
		return "", flowDescErrorf("invalid action")
	}

	// dir
	switch r.Dir {
	case Out:
		ipFilterRuleStr = append(ipFilterRuleStr, "out")
	default:
		return "", flowDescErrorf("for now, only support \"out\" ")
	}

	// proto
	if r.Proto == ProtocolNumberAny {
		ipFilterRuleStr = append(ipFilterRuleStr, "ip")
	} else {
		ipFilterRuleStr = append(ipFilterRuleStr, strconv.Itoa(int(r.Proto)))
	}

	// from
	ipFilterRuleStr = append(ipFilterRuleStr, "from")

	// src
	src := r.Src
	if src != "" {
		if validAddrsFormat(src) {
			ipFilterRuleStr = append(ipFilterRuleStr, src)
		} else {
			return "", flowDescErrorf("source addresses format error %s", src)
		}
	} else {
		ipFilterRuleStr = append(ipFilterRuleStr, "any")
	}

	srcPort := r.SrcPorts.String()
	if srcPort != "" {
		if validPortsFormat(srcPort) {
			ipFilterRuleStr = append(ipFilterRuleStr, srcPort)
		} else {
			return "", flowDescErrorf("source ports format error %s", srcPort)
		}
	}

	// to
	ipFilterRuleStr = append(ipFilterRuleStr, "to")

	// dst
	dst := r.Dst
	if dst != "" {
		if validAddrsFormat(dst) {
			ipFilterRuleStr = append(ipFilterRuleStr, dst)
		} else {
			return "", flowDescErrorf("destination addresses format error %s", dst)
		}
	} else {
		ipFilterRuleStr = append(ipFilterRuleStr, "any")
	}

	dstPort := r.DstPorts.String()
	if dstPort != "" {
		if validPortsFormat(dstPort) {
			ipFilterRuleStr = append(ipFilterRuleStr, dstPort)
		} else {
			return "", flowDescErrorf("destination ports format error %s", dstPort)
		}
	}

	// according TS 29.212 IPFilterRule cannot use [options]

	return strings.Join(ipFilterRuleStr, " "), nil
}

// Decode parsing the string to IPFilterRule
func Decode(s string) (*IPFilterRule, error) {
	s = strings.ToLower(s)
	parts := strings.Fields(s)

	var err error

	r := NewIPFilterRule()
	ptr := 0
	// action
	if ptr >= len(parts) {
		return nil, fmt.Errorf("too few fields %v", len(parts))
	}
	r.Action, err = parseAction(parts[ptr])
	if err != nil {
		return nil, err
	}
	ptr++

	// dir
	if ptr >= len(parts) {
		return nil, fmt.Errorf("too few fields %v", len(parts))
	}
	r.Dir, err = parseDirection(parts[ptr])
	if err != nil {
		return nil, err
	}
	ptr++

	// proto
	if ptr >= len(parts) {
		return nil, fmt.Errorf("too few fields %v", len(parts))
	}
	r.Proto, err = parseProto(parts[ptr])
	if err != nil {
		return nil, err
	}
	ptr++

	// from
	if ptr >= len(parts) {
		return nil, fmt.Errorf("too few fields %v", len(parts))
	}
	if from := parts[ptr]; from != "from" {
		return nil, flowDescErrorf("parse faild: must have 'from'")
	}
	ptr++

	// src
	if ptr >= len(parts) {
		return nil, fmt.Errorf("too few fields %v", len(parts))
	}
	r.Src, err = parseFlowDescAddrs(parts[ptr])
	if err != nil {
		return nil, err
	}
	ptr++

	// source port
	if ptr >= len(parts) {
		return nil, fmt.Errorf("too few fields %v", len(parts))
	}
	sp, err := ParsePorts(parts[ptr])
	if err == nil {
		r.SrcPorts = sp
		ptr++
	}

	// to
	if ptr >= len(parts) {
		return nil, fmt.Errorf("too few fields %v", len(parts))
	}
	if to := parts[ptr]; to != "to" {
		return nil, flowDescErrorf("parse faild: must have 'to'")
	}
	ptr++

	// dst
	if ptr >= len(parts) {
		return nil, fmt.Errorf("too few fields %v", len(parts))
	}
	r.Dst, err = parseFlowDescAddrs(parts[ptr])
	if err != nil {
		return nil, err
	}
	ptr++

	// if end of parts
	if !(len(parts) > ptr) {
		return r, nil
	}

	// destination port
	dp, err := ParsePorts(parts[ptr])
	if err == nil {
		r.DstPorts = dp
	}

	return r, nil
}

func validAddrsFormat(addrs string) bool {
	if addrs == "" {
		return false
	}
	if addrs[0] == '!' {
		return false
	}
	if addrs == "any" || addrs == "assigned" {
		return true
	}
	_, _, err := net.ParseCIDR(addrs)
	if err == nil {
		return true
	}
	ip := net.ParseIP(addrs)
	return ip != nil
}

func parseFlowDescAddrs(addrs string) (string, error) {
	if addrs == "" {
		return "", flowDescErrorf("Empty string")
	}
	if addrs == "any" || addrs == "assigned" {
		return addrs, nil
	}
	if addrs[0] == '!' {
		return "", flowDescErrorf("Base on TS 29.212, ! expression shall not be used")
	}
	_, ipnet, err := net.ParseCIDR(addrs)
	if err == nil {
		return ipnet.String(), nil
	}
	ip := net.ParseIP(addrs)
	if ip != nil {
		return ip.String(), nil
	}
	return "", fmt.Errorf("invalid addresses %v", addrs)
}

func parseAction(act string) (Action, error) {
	action := Action(act)
	switch action {
	case Permit, Deny:
		return action, nil
	default:
		return "", flowDescErrorf("'%s' is not allow, action only accept 'permit' or 'deny'", action)
	}
}

func parseDirection(dir string) (Direction, error) {
	direction := Direction(dir)
	switch direction {
	case Out:
		return direction, nil
	case In:
		return "", flowDescErrorf("dir cannot be 'in' in core-network")
	default:
		return "", flowDescErrorf("'%s' is not allow, dir only accept 'out'", dir)
	}
}

func parseProto(proto string) (uint8, error) {
	if proto == "ip" {
		return ProtocolNumberAny, nil
	} else {
		if proto, err := strconv.Atoi(proto); err != nil {
			return 0, flowDescErrorf("parse proto failed: %s", err)
		} else {
			return uint8(proto), nil
		}
	}
}

func validPortsFormat(ports string) bool {
	if match, err := regexp.MatchString("([ ][0-9]{1,5}([,-][0-9]{1,5})*)?", ports); err != nil || !match {
		return false
	}
	return true
}

func ParsePorts(ports string) (PortRanges, error) {
	if !validPortsFormat(ports) {
		return nil, flowDescErrorf("not valid format of port number")
	}
	ranges := strings.Split(ports, ",")
	PortRanges := []PortRange{}
	for _, r := range ranges {
		var pRange PortRange
		rangeStr := strings.Split(r, "-")
		if len(rangeStr) == 1 {
			p, err := strconv.ParseUint(r, 10, 16)
			if err != nil {
				return nil, err
			}
			pUint16 := uint16(p)
			pRange.Start = pUint16
			pRange.End = pUint16
		} else {
			p0, err := strconv.ParseUint(rangeStr[0], 10, 16)
			if err != nil {
				return nil, err
			}
			p0Uint16 := uint16(p0)
			p1, err := strconv.ParseUint(rangeStr[1], 10, 16)
			if err != nil {
				return nil, err
			}
			p1Uint16 := uint16(p1)
			pRange.Start = p0Uint16
			pRange.End = p1Uint16
		}
		PortRanges = append(PortRanges, pRange)
	}
	return PortRanges, nil
}
