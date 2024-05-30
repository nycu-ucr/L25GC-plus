package test_test

import (
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"test"

	"git.cs.nctu.edu.tw/calee/sctp"
	formatter "github.com/antonfisher/nested-logrus-formatter"
	"github.com/nycu-ucr/CommonConsumerTestData/UDM/TestGenAuthData"
	"github.com/nycu-ucr/nas"
	"github.com/nycu-ucr/nas/nasMessage"
	"github.com/nycu-ucr/nas/nasTestpacket"
	"github.com/nycu-ucr/nas/nasType"
	"github.com/nycu-ucr/nas/security"
	"github.com/nycu-ucr/ngap"
	"github.com/nycu-ucr/ngap/ngapType"
	"github.com/nycu-ucr/openapi/models"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	ranN2Ipv4Addr string = "127.0.0.1"
	amfN2Ipv4Addr string = "127.0.0.18"
	ranN3Ipv4Addr string = "10.100.200.1"
)

// const upfN3Ipv4Addr string = "10.100.200.3"
const (
	testUsedIpAddr string = "127.0.0.5"
	upfServiceId   int    = 1 // upf-u service id
)

const RegLog string = "[TEST][TestRegistration] "

const (
	colorCyan  string = "\033[36m"
	colorReset string = "\033[0m"
	colorGreen string = "\033[32m"
	colorRed   string = "\033[31m"
)

type GnbIdInfo struct {
	id     []byte
	length uint64
	name   string
}

type MobileIdentityGroup struct {
	mobileIdentity5GS nasType.MobileIdentity5GS
	supi              string
	port              int32
	gnbIdInfo         GnbIdInfo
}

type MultiRegTestGroup struct {
	supi   string
	plmnid string
}

var (
	_log               *logrus.Logger
	RegLogger          *logrus.Entry
	HandoverLogger     *logrus.Entry
	PagingLogger       *logrus.Entry
	pdu_sucess_counter uint64
)

func init() {
	_log = logrus.New()
	_log.SetReportCaller(false)

	_log.Formatter = &formatter.Formatter{
		TimestampFormat: time.StampNano,
		TrimMessages:    true,
		NoFieldsSpace:   true,
		HideKeys:        true,
		FieldsOrder:     []string{"component", "category"},
	}

	RegLogger = _log.WithFields(logrus.Fields{"component": "TEST", "category": "Registration"})
	HandoverLogger = _log.WithFields(logrus.Fields{"component": "TEST", "category": "N2Handover"})
	PagingLogger = _log.WithFields(logrus.Fields{"component": "TEST", "category": "Paging"})

	SetLogLevel(logrus.InfoLevel)
}

func SetLogLevel(level logrus.Level) {
	_log.SetLevel(level)
}

func SetReportCaller(set bool) {
	_log.SetReportCaller(set)
}

func CountDown(second int, message string) {
	for x := second; x > -1; x-- {
		fmt.Printf("After %2d seconds will do %v\r", x, message)
		time.Sleep(1 * time.Second)
	}
}

func GenerateMobileIdentityGroup() []MobileIdentityGroup {
	var mcc, mnc, msin int
	var x, y, upper_x, upper_y uint8
	var gnbIdCounter uint32 = 1
	upper_x = 0x9A
	upper_y = 0x9A

	result := make([]MobileIdentityGroup, upper_x*upper_y)
	index := 0
	port := 9487
	for x = 0; x < upper_x; x++ {
		if x%16 >= 10 {
			continue
		}
		for y = 0; y < upper_y; y++ {
			if y%16 >= 10 {
				continue
			}

			result[index].mobileIdentity5GS.Len = 12
			result[index].mobileIdentity5GS.Buffer = []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, x, y}
			result[index].port = int32(port)
			result[index].gnbIdInfo.id = make([]byte, 4)
			binary.BigEndian.PutUint32(result[index].gnbIdInfo.id, gnbIdCounter)
			result[index].gnbIdInfo.length = 32
			result[index].gnbIdInfo.name = fmt.Sprintf("free5gc%d", gnbIdCounter)

			suci := result[index].mobileIdentity5GS.GetSUCI()
			fmt.Sscanf(suci, "suci-0-%d-%d-0-0-0-%d", &mcc, &mnc, &msin)
			supi := fmt.Sprintf("imsi-%d%d%08d", mcc, mnc, msin)

			result[index].supi = supi
			index++
			port++
			gnbIdCounter++

			if index == len(result) {
				result = append(result, result[0])
			}
		}
	}

	return result // size is 10001
}

func FileLogger(fname string, data_ch chan time.Duration) {
	file, err := os.OpenFile(fname, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o666)
	if err != nil {
		RegLogger.Errorf("Open reg_latency.txt, Error: %v\n", err.Error())
		return
	}
	defer file.Close()

	for latency := range data_ch {
		data := fmt.Sprintf("%v\n", latency.Seconds())
		file.WriteString(data)
	}
}

// Registration
func TestRegistration(t *testing.T) {
	var n int
	var sendMsg []byte
	recvMsg := make([]byte, 2048)

	// RAN connect to AMF
	conn, err := test.ConnectToAmf(amfN2Ipv4Addr, ranN2Ipv4Addr, 38412, 9487)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), RegLog, string(colorReset), "RAN connect to AMF")
	} else {
		fmt.Println(string(colorCyan), RegLog, string(colorRed), "RAN Connect To AMF Error", string(colorReset))
	}

	// RAN connect to UPF
	//	upfConn, err := test.ConnectToUpf(ranN3Ipv4Addr, upfN3Ipv4Addr, 2152, 2152)
	//	assert.Nil(t, err)

	// send NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x02"), 24, "free5gc")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), RegLog, string(colorReset), "Send NGSetupRequest Msg")
	} else {
		fmt.Println(string(colorCyan), RegLog, string(colorRed), "Send NGSetupRequest Msg Error", string(colorReset))
	}

	// receive NGSetupResponse Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), RegLog, string(colorReset), "Receive NGSetupResponse Msg")
	} else {
		fmt.Println(string(colorCyan), RegLog, string(colorRed), "Receive NGSetupResponse Msg Error", string(colorReset))
	}
	ngapPdu, err := ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentSuccessfulOutcome && ngapPdu.SuccessfulOutcome.ProcedureCode.Value == ngapType.ProcedureCodeNGSetup, "No NGSetupResponse received.")

	// New UE
	// ue := test.NewRanUeContext("imsi-2089300007487", 1, security.AlgCiphering128NEA2, security.AlgIntegrity128NIA2)
	// ue := test.NewRanUeContext("imsi-2089300007487", 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2)
	ue := test.NewRanUeContext("imsi-2089300007488", 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2)
	ue.AmfUeNgapId = 1
	ue.AuthenticationSubs = test.GetAuthSubscription(TestGenAuthData.MilenageTestSet19.K,
		TestGenAuthData.MilenageTestSet19.OPC,
		TestGenAuthData.MilenageTestSet19.OP)
	// insert UE data to MongoDB

	servingPlmnId := "20893"
	test.InsertAuthSubscriptionToMongoDB(ue.Supi, ue.AuthenticationSubs)
	getData := test.GetAuthSubscriptionFromMongoDB(ue.Supi)
	assert.NotNil(t, getData)
	{
		amData := test.GetAccessAndMobilitySubscriptionData()
		test.InsertAccessAndMobilitySubscriptionDataToMongoDB(ue.Supi, amData, servingPlmnId)
		getData := test.GetAccessAndMobilitySubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)
		assert.NotNil(t, getData)
	}
	{
		smfSelData := test.GetSmfSelectionSubscriptionData()
		test.InsertSmfSelectionSubscriptionDataToMongoDB(ue.Supi, smfSelData, servingPlmnId)
		getData := test.GetSmfSelectionSubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)
		assert.NotNil(t, getData)
	}
	{
		smSelData := test.GetSessionManagementSubscriptionData()
		test.InsertSessionManagementSubscriptionDataToMongoDB(ue.Supi, servingPlmnId, smSelData)
		getData := test.GetSessionManagementDataFromMongoDB(ue.Supi, servingPlmnId)
		assert.NotNil(t, getData)
	}
	{
		amPolicyData := test.GetAmPolicyData()
		test.InsertAmPolicyDataToMongoDB(ue.Supi, amPolicyData)
		getData := test.GetAmPolicyDataFromMongoDB(ue.Supi)
		assert.NotNil(t, getData)
	}
	{
		smPolicyData := test.GetSmPolicyData()
		test.InsertSmPolicyDataToMongoDB(ue.Supi, smPolicyData)
		getData := test.GetSmPolicyDataFromMongoDB(ue.Supi)
		assert.NotNil(t, getData)
	}

	// send InitialUeMessage(Registration Request)(imsi-2089300007487)
	mobileIdentity5GS := nasType.MobileIdentity5GS{
		Len: 12, // suci
		// Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
		Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x47, 0x88},
	}

	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := nasTestpacket.GetRegistrationRequest(
		nasMessage.RegistrationType5GSInitialRegistration, mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "")
	assert.Nil(t, err)

	fmt.Println(string(colorCyan), RegLog, string(colorGreen), "[Start Registration]", string(colorReset))
	t1 := time.Now()

	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), RegLog, string(colorReset), "Send Initial UE Message")
	} else {
		fmt.Println(string(colorCyan), RegLog, string(colorRed), "Send Initial UE Message Error", string(colorReset))
	}

	// receive NAS Authentication Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), RegLog, string(colorReset), "Receive NAS Authentication Request Msg")
	} else {
		fmt.Println(string(colorCyan), RegLog, string(colorRed), "Receive NAS Authentication Request Msg Error", string(colorReset))
	}
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage, "No NGAP Initiating Message received.")

	// Calculate for RES*
	nasPdu := test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeAuthenticationRequest,
		"Received wrong GMM message. Expected Authentication Request.")
	rand := nasPdu.AuthenticationRequest.GetRANDValue()
	resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// send NAS Authentication Response
	pdu := nasTestpacket.GetAuthenticationResponse(resStat, "")
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), RegLog, string(colorReset), "Send NAS Authentication Response")
	} else {
		fmt.Println(string(colorCyan), RegLog, string(colorRed), "Send NAS Authentication Response Error", string(colorReset))
	}

	// receive NAS Security Mode Command Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), RegLog, string(colorReset), "Receive NAS Security Mode Command Msg")
	} else {
		fmt.Println(string(colorCyan), RegLog, string(colorRed), "Receive NAS Security Mode Command Msg Error", string(colorReset))
	}
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.NotNil(t, ngapPdu)
	nasPdu = test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeSecurityModeCommand,
		"Received wrong GMM message. Expected Security Mode Command.")

	// send NAS Security Mode Complete Msg
	registrationRequestWith5GMM := nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, nil)
	pdu = nasTestpacket.GetSecurityModeComplete(registrationRequestWith5GMM)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, true, true)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), RegLog, string(colorReset), "Send NAS Security Mode Complete Msg")
	} else {
		fmt.Println(string(colorCyan), RegLog, string(colorRed), "Send NAS Security Mode Complete Msg Error", string(colorReset))
	}

	// receive ngap Initial Context Setup Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), RegLog, string(colorReset), "Receive NGAP Initial Context Setup Request Msg")
	} else {
		fmt.Println(string(colorCyan), RegLog, string(colorRed), "Receive NGAP Initial Context Setup Request Msg Error", string(colorReset))
	}
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage &&
		ngapPdu.InitiatingMessage.ProcedureCode.Value == ngapType.ProcedureCodeInitialContextSetup,
		"No InitialContextSetup received.")

	// send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), RegLog, string(colorReset), "Send NGAP Initial Context Setup Response Msg")
	} else {
		fmt.Println(string(colorCyan), RegLog, string(colorRed), "Send NGAP Initial Context Setup Response Msg Error", string(colorReset))
	}

	// send NAS Registration Complete Msg
	pdu = nasTestpacket.GetRegistrationComplete(nil)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), RegLog, string(colorReset), "Send NAS Registration Complete Msg")
	} else {
		fmt.Println(string(colorCyan), RegLog, string(colorRed), "Send NAS Registration Complete Msg Error", string(colorReset))
	}

	t2 := time.Now()
	fmt.Println(string(colorCyan), RegLog, string(colorGreen), "[Finish Registration]", string(colorReset), t2.Sub(t1).Seconds(), "(seconds)")
	time.Sleep(time.Millisecond * 500) // Let CN handle Registration Complete
	fmt.Println(string(colorCyan), RegLog, string(colorGreen), "[Start PDU Session Establishment]", string(colorReset))
	t3 := time.Now()

	// send GetPduSessionEstablishmentRequest Msg
	sNssai := models.Snssai{
		Sst: 1,
		Sd:  "010203",
	}
	pdu = nasTestpacket.GetUlNasTransport_PduSessionEstablishmentRequest(10, nasMessage.ULNASTransportRequestTypeInitialRequest, "internet", &sNssai)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), RegLog, string(colorReset), "Send PduSessionEstablishmentRequest Msg")
	} else {
		fmt.Println(string(colorCyan), RegLog, string(colorRed), "Send PduSessionEstablishmentRequest Msg Error", string(colorReset))
	}

	//receive Configuration Update Command
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	// receive 12. NGAP-PDU Session Resource Setup Request(DL nas transport((NAS msg-PDU session setup Accept)))
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), RegLog, string(colorReset), "Receive NGAP-PDU Session Resource Setup Request")
	} else {
		fmt.Println(string(colorCyan), RegLog, string(colorRed), "Receive NGAP-PDU Session Resource Setup Request Error", string(colorReset))
	}
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage &&
		ngapPdu.InitiatingMessage.ProcedureCode.Value == ngapType.ProcedureCodePDUSessionResourceSetup,
		"No PDUSessionResourceSetup received. (%d)", ngapPdu.InitiatingMessage.ProcedureCode.Value)
	fmt.Println(ngapPdu)

	// send 14. NGAP-PDU Session Resource Setup Response
	sendMsg, err = test.GetPDUSessionResourceSetupResponse(10, ue.AmfUeNgapId, ue.RanUeNgapId, ranN3Ipv4Addr)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		fmt.Println(string(colorCyan), RegLog, string(colorReset), "Send NGAP-PDU Session Resource Setup Response")
	} else {
		fmt.Println(string(colorCyan), RegLog, string(colorRed), "Send NGAP-PDU Session Resource Setup Response Error", string(colorReset))
	}

	t4 := time.Now()
	fmt.Println(string(colorCyan), RegLog, string(colorGreen), "[Finish PDU Session Establishment]", string(colorReset), t4.Sub(t3).Seconds(), "(seconds)")
	// wait 1s
	// time.Sleep(1 * time.Second)
	/*
		// Send the dummy packet
		// ping IP(tunnel IP) from 60.60.0.2(127.0.0.1) to 60.60.0.20(127.0.0.8)
		gtpHdr, err := hex.DecodeString("32ff00340000000100000000")
		assert.Nil(t, err)
		icmpData, err := hex.DecodeString("8c870d0000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637")
		assert.Nil(t, err)

		ipv4hdr := ipv4.Header{
			Version:  4,
			Len:      20,
			Protocol: 1,
			Flags:    0,
			TotalLen: 48,
			TTL:      64,
			Src:      net.ParseIP("60.60.0.1").To4(),
			Dst:      net.ParseIP("60.60.0.101").To4(),
			ID:       1,
		}
		checksum := test.CalculateIpv4HeaderChecksum(&ipv4hdr)
		ipv4hdr.Checksum = int(checksum)

		v4HdrBuf, err := ipv4hdr.Marshal()
		assert.Nil(t, err)
		tt := append(gtpHdr, v4HdrBuf...)

		m := icmp.Message{
			Type: ipv4.ICMPTypeEcho, Code: 0,
			Body: &icmp.Echo{
				ID: 12394, Seq: 1,
				Data: icmpData,
			},
		}
		b, err := m.Marshal(nil)
		assert.Nil(t, err)
		b[2] = 0xaf
		b[3] = 0x88
		_, err = upfConn.Write(append(tt, b...))
		assert.Nil(t, err)
	*/
	time.Sleep(1 * time.Second)

	// delete test data
	test.DelAuthSubscriptionToMongoDB(ue.Supi)
	test.DelAccessAndMobilitySubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)
	test.DelSmfSelectionSubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)

	// close Connection
	conn.Close()
	time.Sleep(2 * time.Second)
	// terminate all NF
	//	NfTerminate()
}

func TestNRegistration(t *testing.T) {
	for x := 0; x < 100; x++ {
		TestRegistration(t)
	}
}

func EstablishPduSession(t *testing.T, conn *sctp.SCTPConn, ue *test.RanUeContext) (
	pdu_session_establishment_latency time.Duration, err error,
) {
	var n int
	var sendMsg []byte
	recvMsg := make([]byte, 2048)

	t3 := time.Now()

	// send GetPduSessionEstablishmentRequest Msg
	sNssai := models.Snssai{
		Sst: 1,
		Sd:  "010203",
	}
	pdu := nasTestpacket.GetUlNasTransport_PduSessionEstablishmentRequest(10, nasMessage.ULNASTransportRequestTypeInitialRequest, "internet", &sNssai)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	if err == nil {
		RegLogger.Infof("(%v) Send PduSessionEstablishmentRequest Msg (size=%v)", conn.LocalAddr(), len(sendMsg))
	} else {
		RegLogger.Errorf("(%v) Send PduSessionEstablishmentRequest Msg (size=%v), Error: %v",
			conn.LocalAddr(), len(sendMsg), err)
		return
	}
	n, err = conn.Read(recvMsg)
	// receive 12. NGAP-PDU Session Resource Setup Request(DL nas transport((NAS msg-PDU session setup Accept)))
	n, err = conn.Read(recvMsg)
	if err == nil {
		RegLogger.Infof("(%v) Receive NGAP-PDU Session Resource Setup Request (size=%v)", conn.LocalAddr(), n)
	} else {
		RegLogger.Errorf("(%v) Receive NGAP-PDU Session Resource Setup Request (size=%v), Error: %v",
			conn.LocalAddr(), n, err)
		return
	}
	ngapPdu, err := ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	if !(ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage &&
		ngapPdu.InitiatingMessage.ProcedureCode.Value == ngapType.ProcedureCodePDUSessionResourceSetup) {
		RegLogger.Errorf("(%v) No PDUSessionResourceSetup received.", conn.LocalAddr())
		err = fmt.Errorf("No PDUSessionResourceSetup received")
		return
	}
	address, err := test.GetIpAddressFromPDUSessionResourceSetupRequest(ue, ngapPdu.InitiatingMessage.Value.PDUSessionResourceSetupRequest)
	assert.Nil(t, err)
	ue.PduAddress = address
	atomic.AddUint64(&pdu_sucess_counter, 1)

	// send 14. NGAP-PDU Session Resource Setup Response
	sendMsg, err = test.GetPDUSessionResourceSetupResponse(10, ue.AmfUeNgapId, ue.RanUeNgapId, ranN3Ipv4Addr)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		RegLogger.Infof("(%v) Send NGAP-PDU Session Resource Setup Response (size=%v)", conn.LocalAddr(), len(sendMsg))
	} else {
		RegLogger.Errorf("(%v) Send NGAP-PDU Session Resource Setup Response (size=%v)", conn.LocalAddr(), len(sendMsg))
		return
	}

	t4 := time.Now()
	pdu_session_establishment_latency = t4.Sub(t3)

	return
}

// func SingleRegistration(conn *sctp.SCTPConn, idx int, data MobileIdentityGroup, t *testing.T) (string, string, time.Duration, time.Duration) {
func SingleRegistration(idx int, data MobileIdentityGroup, t *testing.T) (string, string, time.Duration, time.Duration) {
	var n int
	var sendMsg []byte
	var err error
	var registration_latency, pdu_session_establishment_latency time.Duration
	var logMsg string
	var conn *sctp.SCTPConn
	recvMsg := make([]byte, 2048)
	timeout := new(syscall.Timeval)
	timeout.Sec = 10

	// RAN connect to AMF
	for x := 0; x < 100; x++ {
		conn, err = test.ConnectToAmf(amfN2Ipv4Addr, ranN2Ipv4Addr, 38412, int(data.port))
		if err == nil {
			RegLogger.Info("RAN connect to AMF")
			break
		} else {
			RegLogger.Errorf("RAN connect to AMF, Error = %v, Port = %v", err.Error(), data.port)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Set r/w timeout
	err = conn.SetWriteTimeout(*timeout)
	if err != nil {
		RegLogger.Errorf("SetWriteTimeout: %v", err)
	}
	err = conn.SetReadTimeout(*timeout)
	if err != nil {
		RegLogger.Errorf("SetReadTimeout: %v", err)
	}

	// send NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest(
		data.gnbIdInfo.id,
		data.gnbIdInfo.length,
		data.gnbIdInfo.name,
	)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	logMsg = fmt.Sprintf("(%v) Send NGSetupRequest Msg", conn.LocalAddr())
	if err == nil {
		RegLogger.Info(logMsg)
	} else {
		RegLogger.Error(logMsg)
	}

	// receive NGSetupResponse Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	logMsg = fmt.Sprintf("(%v) Receive NGSetupResponse Msg", conn.LocalAddr())
	if err == nil {
		RegLogger.Info(logMsg)
	} else {
		RegLogger.Error(logMsg)
	}
	ngapPdu, err := ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t,
		ngapPdu.Present == ngapType.NGAPPDUPresentSuccessfulOutcome && ngapPdu.SuccessfulOutcome.ProcedureCode.Value == ngapType.ProcedureCodeNGSetup,
		"No NGSetupResponse received.",
	)

	// New UE
	ue := test.NewRanUeContext(data.supi, 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2)
	ue.AmfUeNgapId = int64(idx)
	ue.RanUeNgapId = int64(idx)
	ue.AuthenticationSubs = test.GetAuthSubscription(TestGenAuthData.MilenageTestSet19.K,
		TestGenAuthData.MilenageTestSet19.OPC,
		TestGenAuthData.MilenageTestSet19.OP)
	// insert UE data to MongoDB

	servingPlmnId := "20893"
	test.InsertAuthSubscriptionToMongoDB(ue.Supi, ue.AuthenticationSubs)
	getData := test.GetAuthSubscriptionFromMongoDB(ue.Supi)
	assert.NotNil(t, getData)
	{
		amData := test.GetAccessAndMobilitySubscriptionData()
		test.InsertAccessAndMobilitySubscriptionDataToMongoDB(ue.Supi, amData, servingPlmnId)
		getData := test.GetAccessAndMobilitySubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)
		assert.NotNil(t, getData)
	}
	{
		smfSelData := test.GetSmfSelectionSubscriptionData()
		test.InsertSmfSelectionSubscriptionDataToMongoDB(ue.Supi, smfSelData, servingPlmnId)
		getData := test.GetSmfSelectionSubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)
		assert.NotNil(t, getData)
	}
	{
		smSelData := test.GetSessionManagementSubscriptionData()
		test.InsertSessionManagementSubscriptionDataToMongoDB(ue.Supi, servingPlmnId, smSelData)
		getData := test.GetSessionManagementDataFromMongoDB(ue.Supi, servingPlmnId)
		assert.NotNil(t, getData)
	}
	{
		amPolicyData := test.GetAmPolicyData()
		test.InsertAmPolicyDataToMongoDB(ue.Supi, amPolicyData)
		getData := test.GetAmPolicyDataFromMongoDB(ue.Supi)
		assert.NotNil(t, getData)
	}
	{
		smPolicyData := test.GetSmPolicyData()
		test.InsertSmPolicyDataToMongoDB(ue.Supi, smPolicyData)
		getData := test.GetSmPolicyDataFromMongoDB(ue.Supi)
		assert.NotNil(t, getData)
	}

	// send InitialUeMessage(Registration Request)(imsi-2089300007487)
	mobileIdentity5GS := data.mobileIdentity5GS

	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := nasTestpacket.GetRegistrationRequest(
		nasMessage.RegistrationType5GSInitialRegistration, mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "")
	assert.Nil(t, err)

	RegLogger.Warnln("[Start Registration]")
	t1 := time.Now()

	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	logMsg = fmt.Sprintf("(%v) Send Initial UE Message, (%v)", conn.LocalAddr(), data.supi)
	if err == nil {
		RegLogger.Infof(logMsg)
	} else {
		RegLogger.Error(logMsg)
	}

	// receive NAS Authentication Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	logMsg = fmt.Sprintf("(%v) Receive NAS Authentication Request Msg, (%v)", conn.LocalAddr(), data.supi)
	if err == nil {
		RegLogger.Infof(logMsg)
	} else {
		RegLogger.Error(logMsg)
	}
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage, "No NGAP Initiating Message received. (%v)", data.supi)

	amfUeNgapId := test.GetAmfUeNgapId(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	if amfUeNgapId == nil {
		RegLogger.Errorln("amfUeNgapId is nil")
	} else {
		ue.AmfUeNgapId = amfUeNgapId.Value
	}
	RegLogger.Infof("(Conn, AmfUeNgapId, RanUeNgapId) = (%v, %v, %v)", conn.LocalAddr(), ue.AmfUeNgapId, ue.RanUeNgapId)

	// Calculate for RES*
	nasPdu := test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeAuthenticationRequest,
		"Received wrong GMM message. Expected Authentication Request.")
	rand := nasPdu.AuthenticationRequest.GetRANDValue()
	resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// send NAS Authentication Response
	pdu := nasTestpacket.GetAuthenticationResponse(resStat, "")
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	logMsg = fmt.Sprintf("(%v) Send NAS Authentication Response, (%v)", conn.LocalAddr(), data.supi)
	if err == nil {
		RegLogger.Info(logMsg)
	} else {
		RegLogger.Error(logMsg)
	}

	// receive NAS Security Mode Command Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	logMsg = fmt.Sprintf("(%v) Receive NAS Security Mode Command Msg, (%v)", conn.LocalAddr(), data.supi)
	if err == nil {
		RegLogger.Info(logMsg)
	} else {
		RegLogger.Errorf(logMsg)
	}
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.NotNil(t, ngapPdu)
	nasPdu = test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	require.NotNil(t, nasPdu)
	require.NotNil(t, nasPdu.GmmMessage, "GMM message is nil")
	require.Equal(t, nasPdu.GmmHeader.GetMessageType(), nas.MsgTypeSecurityModeCommand,
		"Received wrong GMM message. Expected Security Mode Command.")

	// send NAS Security Mode Complete Msg
	registrationRequestWith5GMM := nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSInitialRegistration,
		mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, nil)
	pdu = nasTestpacket.GetSecurityModeComplete(registrationRequestWith5GMM)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCipheredWithNew5gNasSecurityContext, true, true)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	logMsg = fmt.Sprintf("(%v) Send NAS Security Mode Complete Msg, (%v)", conn.LocalAddr(), data.supi)
	if err == nil {
		RegLogger.Info(logMsg)
	} else {
		RegLogger.Error(logMsg)
	}

	// receive ngap Initial Context Setup Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	logMsg = fmt.Sprintf("(%v) Receive NGAP Initial Context Setup Request Msg, (%v)", conn.LocalAddr(), data.supi)
	if err == nil {
		RegLogger.Info(logMsg)
	} else {
		RegLogger.Error(logMsg)
	}
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage &&
		ngapPdu.InitiatingMessage.ProcedureCode.Value == ngapType.ProcedureCodeInitialContextSetup,
		"No InitialContextSetup received.")

	// send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	logMsg = fmt.Sprintf("(%v) Send NGAP Initial Context Setup Response Msg, (%v)", conn.LocalAddr(), data.supi)
	if err == nil {
		RegLogger.Info(logMsg)
	} else {
		RegLogger.Error(logMsg)
	}

	// send NAS Registration Complete Msg
	pdu = nasTestpacket.GetRegistrationComplete(nil)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	logMsg = fmt.Sprintf("(%v) Send NAS Registration Complete Msg, (%v)", conn.LocalAddr(), data.supi)
	if err == nil {
		RegLogger.Info(logMsg)
	} else {
		RegLogger.Error(logMsg)
	}

	t2 := time.Now()
	registration_latency = t2.Sub(t1)
	RegLogger.Warnf("[Finish Registration]: %.9f (seconds)", registration_latency.Seconds())
	time.Sleep(time.Second * 1) // Let CN handle Registration Complete
	RegLogger.Warnln("[Start PDU Session Establishment]")
	for i := 0; i < 1; i++ {
		pdu_session_establishment_latency, err = EstablishPduSession(t, conn, ue)
		if err == nil {
			break
		}
	}
	RegLogger.Warnf("[Finish PDU Session Establishment]: %.9f (seconds)", pdu_session_establishment_latency.Seconds())
	
	time.Sleep(1 * time.Second)
	// close Connection
	conn.Close() // TODO: Try don't close
	// time.Sleep(2 * time.Second)
	time.Sleep(1 * time.Second)

	return ue.Supi, servingPlmnId, registration_latency, pdu_session_establishment_latency
}

type WorkData struct {
	id                   int
	mobile_identiy_group MobileIdentityGroup
}

func RegistrationWorker(name string,
	wg *sync.WaitGroup,
	work_data_array []WorkData,
	reg_latency_chan chan time.Duration,
	pdu_latency_chan chan time.Duration,
	t *testing.T,
) {
	// fmt.Println(name, "start")
	// var conn *sctp.SCTPConn
	// var sendMsg []byte
	// var err error
	// recvMsg := make([]byte, 2048)

	// RAN connect to AMF
	// conn, err = test.ConnectToAmf(amfN2Ipv4Addr, ranN2Ipv4Addr, 38412, int(work_data_array[0].mobile_identiy_group.port))
	// if err != nil {
	// 	RegLogger.Errorf("RAN connect to AMF, Error = %v, Port = %v", err.Error(), work_data_array[0].mobile_identiy_group.port)
	// 	return
	// }

	// timeout := new(syscall.Timeval)
	// timeout.Sec = 5

	// // Set r/w timeout
	// err = conn.SetWriteTimeout(*timeout)
	// if err != nil {
	// 	RegLogger.Errorf("SetWriteTimeout: %v", err)
	// }
	// err = conn.SetReadTimeout(*timeout)
	// if err != nil {
	// 	RegLogger.Errorf("SetReadTimeout: %v", err)
	// }

	// send NGSetupRequest Msg
	// sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x02"), 24, "free5gc")
	// sendMsg, err = test.GetNGSetupRequest(
	// 	work_data_array[0].mobile_identiy_group.gnbIdInfo.id,
	// 	work_data_array[0].mobile_identiy_group.gnbIdInfo.length,
	// 	work_data_array[0].mobile_identiy_group.gnbIdInfo.name,
	// )
	// assert.Nil(t, err)
	// _, err = conn.Write(sendMsg)
	// assert.Nil(t, err)
	// if err == nil {
	// 	RegLogger.Info("Send NGSetupRequest Msg")
	// } else {
	// 	RegLogger.Error("Send NGSetupRequest Msg")
	// }

	// // receive NGSetupResponse Msg
	// n, err := conn.Read(recvMsg)
	// assert.Nil(t, err)
	// if err == nil {
	// 	RegLogger.Info("Receive NGSetupResponse Msg")
	// } else {
	// 	RegLogger.Error("Receive NGSetupResponse Msg")
	// }
	// ngapPdu, err := ngap.Decoder(recvMsg[:n])
	// assert.Nil(t, err)
	// assert.True(t,
	// 	ngapPdu.Present == ngapType.NGAPPDUPresentSuccessfulOutcome &&
	// 		ngapPdu.SuccessfulOutcome.ProcedureCode.Value ==
	// 			ngapType.ProcedureCodeNGSetup,
	// 	"No NGSetupResponse received.",
	// )

	for _, work_data := range work_data_array {
		// fmt.Println(name, "handle id", work_data.id)
		// _, _, reg_latency, pdu_latency := SingleRegistration(conn, work_data.id+1, work_data.mobile_identiy_group, t)
		_, _, reg_latency, pdu_latency := SingleRegistration(work_data.id+1, work_data.mobile_identiy_group, t)
		reg_latency_chan <- reg_latency
		pdu_latency_chan <- pdu_latency
	}
	wg.Done()
	// fmt.Println(name, "done")
}

func StringToInteger(str string) (int, error) {
    intValue, err := strconv.Atoi(str)
    if err != nil {
        return 0, err
    }
    return intValue, nil
}


func TestMultiRegistrationConcurrent(t *testing.T) {	
	SetLogLevel(logrus.ErrorLevel)

	thread_amount, err := StringToInteger(os.Args[6])
	if err != nil {
        t.Errorf("Invalid thread_amount: %s", err)
        return
    }
	work_load, err := StringToInteger(os.Args[7])
	if err != nil {
        t.Errorf("Invalid work_load: %s", err)
        return
    }
	is_wait := os.Args[8]
	wait_time := 0
	if is_wait == "y" {
		var err error
		wait_time, err = StringToInteger(os.Args[9])
		if err != nil {
			t.Errorf("Invalid wait_time: %s", err)
			return
		}
	}
	amount := thread_amount * work_load

	mobile_identiy_groups := GenerateMobileIdentityGroup()[:amount]
	reg_latency_chan := make(chan time.Duration, amount+1)
	pdu_latency_chan := make(chan time.Duration, amount+1)
	// work_data_chan := make(chan WorkData, amount+1)
	work_data_array := make([]WorkData, amount)

	wg := new(sync.WaitGroup)

	go FileLogger("reg_latency.txt", reg_latency_chan)
	go FileLogger("pdu_latency.txt", pdu_latency_chan)

	for x := 0; x < amount; x++ {
		work_data_array[x] = WorkData{
			id:                   x,
			mobile_identiy_group: mobile_identiy_groups[x],
		}
	}

	wg.Add(thread_amount)
	for x := 0; x < thread_amount; x++ {
		// go Worker(wg, work_data_chan, reg_latency_chan, pdu_latency_chan, t)
		name := fmt.Sprintf("Worker%d", x)
		// fmt.Println("From", work_data_array[x*work_load].id, "To", work_data_array[x*work_load+(work_load-1)].id)
		go RegistrationWorker(name, wg, work_data_array[x*work_load:x*work_load+(work_load)], reg_latency_chan, pdu_latency_chan, t)
		if is_wait == "y" {
			time.Sleep(time.Duration(wait_time) * time.Millisecond)
		}
	}
	wg.Wait()

	close(reg_latency_chan)
	close(pdu_latency_chan)
	time.Sleep(5 * time.Second) // Let FileLogger have encough time to write data
	fmt.Println("MultiRegistrationConcurrent Done: ", pdu_sucess_counter)
}
