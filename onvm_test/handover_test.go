package test_test

import (
	"fmt"
	"reflect"
	"sync"
	"syscall"
	"test"
	"testing"
	"time"
	"os"
	
	"git.cs.nctu.edu.tw/calee/sctp"
	"github.com/mohae/deepcopy"
	"github.com/nycu-ucr/CommonConsumerTestData/UDM/TestGenAuthData"
	"github.com/nycu-ucr/nas"
	"github.com/nycu-ucr/nas/nasMessage"
	"github.com/nycu-ucr/nas/nasTestpacket"
	"github.com/nycu-ucr/nas/nasType"
	"github.com/nycu-ucr/nas/security"
	"github.com/nycu-ucr/ngap"
	"github.com/nycu-ucr/onvmpoller"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

)

type Container struct {
	mu      sync.Mutex
	counter int
}

func (c *Container) block() {
	c.mu.Lock()
	//time.Sleep(10 * time.Millisecond)
	defer c.mu.Unlock()
}

func (c *Container) inc() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counter++
}

func (c *Container) dec() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.counter--
}

type TimeAndMsg struct {
	msg     string
	t_start time.Time
	t_end   time.Time
}

var LockForHandover Container

/*
Registration ->
PDU Session Establishment ->
Source RAN Send Handover Required ->
N2 Handover (Preparation Phase -> Execution Phase)
*/
func TestN2Handover(t *testing.T) {
	var n int
	var sendMsg []byte
	recvMsg := make([]byte, 2048)

	// latency_infos := make([]TimeAndMsg, 20)
	// latency_info := TimeAndMsg{
	// 	msg: "",
	// }
	// latency_infos_idx := 0

	trigger_better_sleep := false

	// RAN1 connect to AMF
	conn, err := test.ConnectToAmf(amfN2Ipv4Addr, ranN2Ipv4Addr, 38412, 9487)
	HandoverLogger.Infoln("type of conn = %s", reflect.TypeOf(conn))
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("RAN1 Connect to AMF")
	} else {
		HandoverLogger.Errorln("RAN1 Connect To AMF Error")
	}

	/*	// RAN1 connect to UPF
		upfConn, err := test.ConnectToUpf(ranN3Ipv4Addr, "10.200.200.102", 2152, 2152)
		assert.Nil(t, err)
	*/
	// RAN1 send NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x01"), 24, "free5gc")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("RAN1 Send NGSetupRequest Msg")
	} else {
		HandoverLogger.Errorln("RAN1 Send NGSetupRequest Msg Error")
	}

	// RAN1 receive NGSetupResponse Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("RAN1 Receive NGSetupResponse Msg")
	} else {
		HandoverLogger.Errorln("RAN1 Receive NGSetupResponse Msg Error")
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	time.Sleep(10 * time.Millisecond)

	// RAN2 connect to AMF
	conn2, err1 := test.ConnectToAmf(amfN2Ipv4Addr, ranN2Ipv4Addr, 38412, 9488)
	assert.Nil(t, err1)
	if err1 == nil {
		HandoverLogger.Infoln("RAN2 Connect to AMF")
	} else {
		HandoverLogger.Errorln("RAN2 Connect to AMF")
	}

	/*	// RAN2 connect to UPF
		upfConn2, err := test.ConnectToUpf("10.200.200.2", "10.200.200.102", 2152, 2152)
		assert.Nil(t, err)
	*/
	// RAN2 send Second NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x02"), 24, "nctu")
	assert.Nil(t, err)
	_, err = conn2.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("RAN2 Send Second NGSetupRequest Msg")
	} else {
		HandoverLogger.Errorln("RAN2 Send Second NGSetupRequest Msg")
	}

	// RAN2 receive Second NGSetupResponse Msg
	n, err = conn2.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("RAN2 Receive Second NGSetupResponse Msg")
	} else {
		HandoverLogger.Errorln("RAN2 Receive Second NGSetupResponse Msg")
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// New UE
	ue := test.NewRanUeContext("imsi-2089300000001", 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2)
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
		Len:    12,                                                                              // suci
		Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10}, // 4778
	}
	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := nasTestpacket.GetRegistrationRequest(
		nasMessage.RegistrationType5GSInitialRegistration, mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "")
	assert.Nil(t, err)

	HandoverLogger.Warnln("[Start Registration]")
	t1 := time.Now()

	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("Send Initial UE Message")
	} else {
		HandoverLogger.Errorln("Send Initial UE Message")
	}

	// receive NAS Authentication Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("Receive NAS Authentication Request Msg")
	} else {
		HandoverLogger.Errorln("Receive NAS Authentication Request Msg")
	}
	ngapMsg, err := ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// Calculate for RES*
	nasPdu := test.GetNasPdu(ue, ngapMsg.InitiatingMessage.Value.DownlinkNASTransport)
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
		HandoverLogger.Infoln("Send NAS Authentication Response")
	} else {
		HandoverLogger.Errorln("Send NAS Authentication Response")
	}

	// receive NAS Security Mode Command Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("Receive NAS Security Mode Command Msg")
	} else {
		HandoverLogger.Errorln("Receive NAS Security Mode Command Msg")
	}
	ngapPdu, err := ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)
	require.NotNil(t, ngapPdu)
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
		HandoverLogger.Infoln("Send NAS Security Mode Complete Msg")
	} else {
		HandoverLogger.Errorln("Send NAS Security Mode Complete Msg")
	}

	// receive ngap Initial Context Setup Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("Receive NGAP Initial Context Setup Request Msg")
	} else {
		HandoverLogger.Errorln("Receive NGAP Initial Context Setup Request Msg")
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("Send NGAP Initial Context Setup Response Msg")
	} else {
		HandoverLogger.Errorln("Send NGAP Initial Context Setup Response Msg")
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
		HandoverLogger.Infoln("Send NAS Registration Complete Msg")
	} else {
		HandoverLogger.Errorln("Send NAS Registration Complete Msg")
	}

	t2 := time.Now()
	HandoverLogger.Warnf("[Finish Registration]: %v (seconds)\n", t2.Sub(t1).Seconds())
	if trigger_better_sleep {
		// If sleep, latency of PDU session establishment will faster in both free5C and XIO-free5GC cases. But why?
		// Because this sleep will absorb the Step 22. and the following steps
		time.Sleep(1 * time.Second)
	}
	HandoverLogger.Warnln("[Start PDU Session Establishment]")
	pdu_session_establishment_latency, err := EstablishPduSession(t, conn, ue)
	HandoverLogger.Warnf("[Finish PDU Session Establishment]: %v (seconds)\n", pdu_session_establishment_latency.Seconds())

	time.Sleep(1 * time.Second)

	/*	// Send the dummy packet to test if UE is connected to RAN1
		// ping IP(tunnel IP) from 60.60.0.1(127.0.0.1) to 60.60.0.100(127.0.0.8)
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
		assert.Nil(t, err)

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

	// ============================================

	// Source RAN send ngap Handover Required Msg
	HandoverLogger.Warnln("[Start NGAP Handlover]")
	// time.Sleep(time.Second * 20)
	t5 := time.Now()

	// latency_info.msg = "Handover Preparation Phase"
	// latency_info.t_start = time.Now()
	// latency_info.msg = "Source RAN send out 1. Handover Required"
	// latency_info.t_start = time.Now()
	sendMsg, err = test.GetHandoverRequired(ue.AmfUeNgapId, ue.RanUeNgapId, []byte{0x00, 0x01, 0x02}, []byte{0x01, 0x20})
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	// latency_info.t_end = time.Now()
	// latency_infos[latency_infos_idx] = latency_info
	// latency_infos_idx++
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("Source RAN Send NGAP Handover Required Msg")
	} else {
		HandoverLogger.Errorln("Source RAN Send NGAP Handover Required Msg")
	}

	// Target RAN receive ngap Handover Request
	// latency_info.msg = "Target RAN wait for 9. Handover Request"
	// latency_info.t_start = time.Now()
	n, err = conn2.Read(recvMsg)
	// latency_info.t_end = time.Now()
	// latency_infos[latency_infos_idx] = latency_info
	// latency_infos_idx++
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("Target RAN Receive NGAP Handover Request")
	} else {
		HandoverLogger.Errorln("Target RAN Receive NGAP Handover Request")
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// Target RAN create New UE
	// latency_info.msg = "DeepCopy UE to Target UE"
	// latency_info.t_start = time.Now()
	targetUe := deepcopy.Copy(ue).(*test.RanUeContext)
	targetUe.AmfUeNgapId = 2
	targetUe.ULCount.Set(ue.ULCount.Overflow(), ue.ULCount.SQN())
	targetUe.DLCount.Set(ue.DLCount.Overflow(), ue.DLCount.SQN())
	// latency_info.t_end = time.Now()
	// latency_infos[latency_infos_idx] = latency_info
	// latency_infos_idx++

	// Target RAN send ngap Handover Request Acknowledge Msg
	sendMsg, err = test.GetHandoverRequestAcknowledge(targetUe.AmfUeNgapId, targetUe.RanUeNgapId)
	assert.Nil(t, err)
	// latency_info.msg = "Target RAN send out 10. Handover Request ACK"
	// latency_info.t_start = time.Now()
	_, err = conn2.Write(sendMsg)
	// latency_info.t_end = time.Now()
	// latency_infos[latency_infos_idx] = latency_info
	// latency_infos_idx++
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("Target RAN Send NGAP Handover Request Acknowledge Msg")
	} else {
		HandoverLogger.Errorln("Target RAN Send NGAP Handover Request Acknowledge Msg")
	}
	// latency_info.t_end = time.Now()
	// latency_infos[latency_infos_idx] = latency_info
	// latency_infos_idx++
	// End of Preparation phase
	// time.Sleep(10 * time.Millisecond)
	HandoverLogger.Infoln("End of Preparation phase")

	// Beginning of Execution

	// Source RAN receive ngap Handover Command
	// latency_info.msg = "Source RAN wait for 1. Handover Command"
	// latency_info.t_start = time.Now()
	n, err = conn.Read(recvMsg)
	// latency_info.t_end = time.Now()
	// latency_infos[latency_infos_idx] = latency_info
	// latency_infos_idx++
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("Source RAN Receive NGAP Handover Command")
	} else {
		HandoverLogger.Errorln("Source RAN Receive NGAP Handover Command")
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// Target RAN send ngap Handover Notify
	// CountDown(10, "send Handover Notify")
	if err != nil {
		HandoverLogger.Errorln(err.Error())
	}
	sendMsg, err = test.GetHandoverNotify(targetUe.AmfUeNgapId, targetUe.RanUeNgapId)
	assert.Nil(t, err)
	// latency_info.msg = "Target RAN send out 5. Handover Notify"
	// latency_info.t_start = time.Now()
	_, err = conn2.Write(sendMsg)
	// latency_info.t_end = time.Now()
	// latency_infos[latency_infos_idx] = latency_info
	// latency_infos_idx++
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("Target RAN Send NGAP Handover Notify")
	} else {
		HandoverLogger.Errorln("Target RAN Send NGAP Handover Notify")
	}

	// Source RAN receive ngap UE Context Release Command
	// latency_info.msg = "Source RAN wait for 14(a). UE Context Release Command"
	// latency_info.t_start = time.Now()
	n, err = conn.Read(recvMsg)
	// latency_info.t_end = time.Now()
	// latency_infos[latency_infos_idx] = latency_info
	// latency_infos_idx++
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("Source RAN Receive NGAP UE Context Release Command")
	} else {
		HandoverLogger.Errorln("Source RAN Receive NGAP UE Context Release Command")
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// Source RAN send ngap UE Context Release Complete
	// CountDown(10, "send UE Context Release Command Complete")
	// latency_info.msg = "Source RAN send out for 14(b). UE Context Release Command Complete"
	// latency_info.t_start = time.Now()
	pduSessionIDList := []int64{10}
	sendMsg, err = test.GetUEContextReleaseComplete(ue.AmfUeNgapId, ue.RanUeNgapId, pduSessionIDList)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	// latency_info.t_end = time.Now()
	// latency_infos[latency_infos_idx] = latency_info
	// latency_infos_idx++
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("Source RAN Send NGAP UE Context Release Complete")
	} else {
		HandoverLogger.Errorln("Source RAN Send NGAP UE Context Release Complete")
	}

	// CountDown(10, "UE Send NAS Registration Request(Mobility Registration Update) To Target AMF")
	// UE send NAS Registration Request(Mobility Registration Update) To Target AMF (2 AMF scenario not supportted yet)
	// latency_info.msg = "UE send NAS Registration Request To Target AMF"
	// latency_info.t_start = time.Now()
	mobileIdentity5GS = nasType.MobileIdentity5GS{
		Len:    11, // 5g-guti
		Buffer: []uint8{0x02, 0x02, 0xf8, 0x39, 0xca, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x01},
	}
	uplinkDataStatus := nasType.NewUplinkDataStatus(nasMessage.RegistrationRequestUplinkDataStatusType)
	uplinkDataStatus.SetLen(2)
	uplinkDataStatus.SetPSI10(1)
	ueSecurityCapability = targetUe.GetUESecurityCapability()
	pdu = nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSMobilityRegistrationUpdating,
		mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, uplinkDataStatus)
	pdu, err = test.EncodeNasPduWithSecurity(targetUe, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(targetUe.AmfUeNgapId, targetUe.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn2.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("UE Send NAS Registration Request(Mobility Registration Update) To Target AMF")
	} else {
		HandoverLogger.Errorln("UE Send NAS Registration Request(Mobility Registration Update) To Target AMF")
	}

	// Target RAN receive ngap Initial Context Setup Request Msg
	// latency_info.msg = "Target RAN Wait for NGAP Initial Context Setup Request Msg"
	// latency_info.t_start = time.Now()
	n, err = conn2.Read(recvMsg)
	// latency_info.t_end = time.Now()
	// latency_infos[latency_infos_idx] = latency_info
	// latency_infos_idx++
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("Target RAN Receive NGAP Initial Context Setup Request Msg")
	} else {
		HandoverLogger.Errorln("Target RAN Receive NGAP Initial Context Setup Request Msg")
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// Target RAN send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetPDUSessionResourceSetupResponseForPaging(targetUe.AmfUeNgapId, targetUe.RanUeNgapId, "10.200.200.2")
	assert.Nil(t, err)
	_, err = conn2.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("Target RAN Send NGAP Initial Context Setup Response Msg")
	} else {
		HandoverLogger.Errorln("Target RAN Send NGAP Initial Context Setup Response Msg")
	}

	// Target RAN send NAS Registration Complete Msg
	pdu = nasTestpacket.GetRegistrationComplete(nil)
	pdu, err = test.EncodeNasPduWithSecurity(targetUe, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(targetUe.AmfUeNgapId, targetUe.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn2.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("Target RAN Send NAS Registration Complete Msg")
	} else {
		HandoverLogger.Errorln("Target RAN Send NAS Registration Complete Msg")
	}
	// latency_info.t_end = time.Now()
	// latency_infos[latency_infos_idx] = latency_info
	// latency_infos_idx++

	t6 := time.Now()
	HandoverLogger.Warnf("[Finish NGAP Handover]: %v (seconds)\n", t6.Sub(t5).Seconds())

	// for i := 0; i < latency_infos_idx; i++ {
	// 	fmt.Printf("Latency: %.9f\tMsg: %v\n", latency_infos[i].t_end.Sub(latency_infos[i].t_start).Seconds(), latency_infos[i].msg)
	// }

	// wait 1000 ms
	time.Sleep(1000 * time.Millisecond)

	// Send the dummy packet
	// ping IP(tunnel IP) from 60.60.0.2(127.0.0.1) to 60.60.0.20(127.0.0.8)
	//	_, err = upfConn2.Write(append(tt, b...))
	//	assert.Nil(t, err)

	time.Sleep(100 * time.Millisecond)

	// delete test data
	test.DelAuthSubscriptionToMongoDB(ue.Supi)
	test.DelAccessAndMobilitySubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)
	test.DelSmfSelectionSubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)

	// close Connection
	conn.Close()
	conn2.Close()

	// onvmpoller.CloseONVM()

	// terminate all NF
	//	NfTerminate()
}


func TestMultiN2Handover(t *testing.T) {
	var workload = 10
	var n int
	var sendMsg []byte
	recvMsg := make([]byte, 2048)

	// latency_infos := make([]TimeAndMsg, 20)
	// latency_info := TimeAndMsg{
	// 	msg: "",
	// }
	// latency_infos_idx := 0

	trigger_better_sleep := false

	// RAN1 connect to AMF
	conn, err := test.ConnectToAmf(amfN2Ipv4Addr, ranN2Ipv4Addr, 38412, 9487)
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("RAN1 Connect to AMF")
	} else {
		HandoverLogger.Errorln("RAN1 Connect To AMF Error")
	}

	/*	// RAN1 connect to UPF
		upfConn, err := test.ConnectToUpf(ranN3Ipv4Addr, "10.200.200.102", 2152, 2152)
		assert.Nil(t, err)
	*/
	// RAN1 send NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x01"), 24, "free5gc")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("RAN1 Send NGSetupRequest Msg")
	} else {
		HandoverLogger.Errorln("RAN1 Send NGSetupRequest Msg Error")
	}

	// RAN1 receive NGSetupResponse Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("RAN1 Receive NGSetupResponse Msg")
	} else {
		HandoverLogger.Errorln("RAN1 Receive NGSetupResponse Msg Error")
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	time.Sleep(10 * time.Millisecond)

	// RAN2 connect to AMF
	conn2, err1 := test.ConnectToAmf(amfN2Ipv4Addr, ranN2Ipv4Addr, 38412, 9488)
	assert.Nil(t, err1)
	if err1 == nil {
		HandoverLogger.Infoln("RAN2 Connect to AMF")
	} else {
		HandoverLogger.Errorln("RAN2 Connect to AMF")
	}

	/*	// RAN2 connect to UPF
		upfConn2, err := test.ConnectToUpf("10.200.200.2", "10.200.200.102", 2152, 2152)
		assert.Nil(t, err)
	*/
	// RAN2 send Second NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x02"), 24, "nctu")
	assert.Nil(t, err)
	_, err = conn2.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("RAN2 Send Second NGSetupRequest Msg")
	} else {
		HandoverLogger.Errorln("RAN2 Send Second NGSetupRequest Msg")
	}

	// RAN2 receive Second NGSetupResponse Msg
	n, err = conn2.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("RAN2 Receive Second NGSetupResponse Msg")
	} else {
		HandoverLogger.Errorln("RAN2 Receive Second NGSetupResponse Msg")
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// New UE
	ue := test.NewRanUeContext("imsi-2089300000001", 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2)
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
		Len:    12,                                                                              // suci
		Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10}, // 4778
	}
	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := nasTestpacket.GetRegistrationRequest(
		nasMessage.RegistrationType5GSInitialRegistration, mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "")
	assert.Nil(t, err)

	HandoverLogger.Warnln("[Start Registration]")
	t1 := time.Now()

	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("Send Initial UE Message")
	} else {
		HandoverLogger.Errorln("Send Initial UE Message")
	}

	// receive NAS Authentication Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("Receive NAS Authentication Request Msg")
	} else {
		HandoverLogger.Errorln("Receive NAS Authentication Request Msg")
	}
	ngapMsg, err := ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// Calculate for RES*
	nasPdu := test.GetNasPdu(ue, ngapMsg.InitiatingMessage.Value.DownlinkNASTransport)
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
		HandoverLogger.Infoln("Send NAS Authentication Response")
	} else {
		HandoverLogger.Errorln("Send NAS Authentication Response")
	}

	// receive NAS Security Mode Command Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("Receive NAS Security Mode Command Msg")
	} else {
		HandoverLogger.Errorln("Receive NAS Security Mode Command Msg")
	}
	ngapPdu, err := ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)
	require.NotNil(t, ngapPdu)
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
		HandoverLogger.Infoln("Send NAS Security Mode Complete Msg")
	} else {
		HandoverLogger.Errorln("Send NAS Security Mode Complete Msg")
	}

	// receive ngap Initial Context Setup Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("Receive NGAP Initial Context Setup Request Msg")
	} else {
		HandoverLogger.Errorln("Receive NGAP Initial Context Setup Request Msg")
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("Send NGAP Initial Context Setup Response Msg")
	} else {
		HandoverLogger.Errorln("Send NGAP Initial Context Setup Response Msg")
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
		HandoverLogger.Infoln("Send NAS Registration Complete Msg")
	} else {
		HandoverLogger.Errorln("Send NAS Registration Complete Msg")
	}

	t2 := time.Now()
	HandoverLogger.Warnf("[Finish Registration]: %v (seconds)\n", t2.Sub(t1).Seconds())
	if trigger_better_sleep {
		// If sleep, latency of PDU session establishment will faster in both free5C and XIO-free5GC cases. But why?
		// Because this sleep will absorb the Step 22. and the following steps
		time.Sleep(1 * time.Second)
	}
	HandoverLogger.Warnln("[Start PDU Session Establishment]")
	pdu_session_establishment_latency, err := EstablishPduSession(t, conn, ue)
	HandoverLogger.Warnf("[Finish PDU Session Establishment]: %v (seconds)\n", pdu_session_establishment_latency.Seconds())

	time.Sleep(1 * time.Second)

	/*	// Send the dummy packet to test if UE is connected to RAN1
		// ping IP(tunnel IP) from 60.60.0.1(127.0.0.1) to 60.60.0.100(127.0.0.8)
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
		assert.Nil(t, err)

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

	// ============================================

	// Source RAN send ngap Handover Required Msg
	var two_conn [2]*sctp.SCTPConn
	var two_gnbID [2][]byte
	two_conn[0] = conn
	two_conn[1] = conn2
	two_gnbID[0] = []byte{0x00, 0x01, 0x01}
	two_gnbID[1] = []byte{0x00, 0x01, 0x02}
	now_connected := 0
	handover_to := 1
	for i := 0; i < workload; i++ {
		HandoverLogger.Warnln("[Start NGAP Handlover]")
		// time.Sleep(time.Second * 20)
		t5 := time.Now()

		// latency_info.msg = "Handover Preparation Phase"
		// latency_info.t_start = time.Now()
		// latency_info.msg = "Source RAN send out 1. Handover Required"
		// latency_info.t_start = time.Now()
		sendMsg, err = test.GetHandoverRequired(ue.AmfUeNgapId, ue.RanUeNgapId, two_gnbID[handover_to], []byte{0x01, 0x20})
		assert.Nil(t, err)
		_, err = two_conn[now_connected].Write(sendMsg)
		// latency_info.t_end = time.Now()
		// latency_infos[latency_infos_idx] = latency_info
		// latency_infos_idx++
		assert.Nil(t, err)
		if err == nil {
			HandoverLogger.Infoln("Source RAN Send NGAP Handover Required Msg")
		} else {
			HandoverLogger.Errorln("Source RAN Send NGAP Handover Required Msg")
		}

		// Target RAN receive ngap Handover Request
		// latency_info.msg = "Target RAN wait for 9. Handover Request"
		// latency_info.t_start = time.Now()
		n, err = two_conn[handover_to].Read(recvMsg)
		// latency_info.t_end = time.Now()
		// latency_infos[latency_infos_idx] = latency_info
		// latency_infos_idx++
		assert.Nil(t, err)
		if err == nil {
			HandoverLogger.Infoln("Target RAN Receive NGAP Handover Request")
		} else {
			HandoverLogger.Errorln("Target RAN Receive NGAP Handover Request")
		}
		_, err = ngap.Decoder(recvMsg[:n])
		assert.Nil(t, err)

		// Target RAN create New UE
		// latency_info.msg = "DeepCopy UE to Target UE"
		// latency_info.t_start = time.Now()
		targetUe := deepcopy.Copy(ue).(*test.RanUeContext)
		targetUe.AmfUeNgapId = int64(i + 2)
		targetUe.ULCount.Set(ue.ULCount.Overflow(), ue.ULCount.SQN())
		targetUe.DLCount.Set(ue.DLCount.Overflow(), ue.DLCount.SQN())
		// latency_info.t_end = time.Now()
		// latency_infos[latency_infos_idx] = latency_info
		// latency_infos_idx++

		// Target RAN send ngap Handover Request Acknowledge Msg
		sendMsg, err = test.GetHandoverRequestAcknowledge(targetUe.AmfUeNgapId, targetUe.RanUeNgapId)
		assert.Nil(t, err)
		// latency_info.msg = "Target RAN send out 10. Handover Request ACK"
		// latency_info.t_start = time.Now()
		_, err = two_conn[handover_to].Write(sendMsg)
		// latency_info.t_end = time.Now()
		// latency_infos[latency_infos_idx] = latency_info
		// latency_infos_idx++
		assert.Nil(t, err)
		if err == nil {
			HandoverLogger.Infoln("Target RAN Send NGAP Handover Request Acknowledge Msg")
		} else {
			HandoverLogger.Errorln("Target RAN Send NGAP Handover Request Acknowledge Msg")
		}
		// latency_info.t_end = time.Now()
		// latency_infos[latency_infos_idx] = latency_info
		// latency_infos_idx++
		// End of Preparation phase
		// time.Sleep(10 * time.Millisecond)
		HandoverLogger.Infoln("End of Preparation phase")

		// Beginning of Execution

		// Source RAN receive ngap Handover Command
		// latency_info.msg = "Source RAN wait for 1. Handover Command"
		// latency_info.t_start = time.Now()
		n, err = two_conn[now_connected].Read(recvMsg)
		// latency_info.t_end = time.Now()
		// latency_infos[latency_infos_idx] = latency_info
		// latency_infos_idx++
		assert.Nil(t, err)
		if err == nil {
			HandoverLogger.Infoln("Source RAN Receive NGAP Handover Command")
		} else {
			HandoverLogger.Errorln("Source RAN Receive NGAP Handover Command")
		}
		_, err = ngap.Decoder(recvMsg[:n])
		assert.Nil(t, err)

		// Target RAN send ngap Handover Notify
		// CountDown(10, "send Handover Notify")
		if err != nil {
			HandoverLogger.Errorln(err.Error())
		}
		sendMsg, err = test.GetHandoverNotify(targetUe.AmfUeNgapId, targetUe.RanUeNgapId)
		assert.Nil(t, err)
		// latency_info.msg = "Target RAN send out 5. Handover Notify"
		// latency_info.t_start = time.Now()
		_, err = two_conn[handover_to].Write(sendMsg)
		// latency_info.t_end = time.Now()
		// latency_infos[latency_infos_idx] = latency_info
		// latency_infos_idx++
		assert.Nil(t, err)
		if err == nil {
			HandoverLogger.Infoln("Target RAN Send NGAP Handover Notify")
		} else {
			HandoverLogger.Errorln("Target RAN Send NGAP Handover Notify")
		}

		// Source RAN receive ngap UE Context Release Command
		// latency_info.msg = "Source RAN wait for 14(a). UE Context Release Command"
		// latency_info.t_start = time.Now()
		n, err = two_conn[now_connected].Read(recvMsg)
		// latency_info.t_end = time.Now()
		// latency_infos[latency_infos_idx] = latency_info
		// latency_infos_idx++
		assert.Nil(t, err)
		if err == nil {
			HandoverLogger.Infoln("Source RAN Receive NGAP UE Context Release Command")
		} else {
			HandoverLogger.Errorln("Source RAN Receive NGAP UE Context Release Command")
		}
		_, err = ngap.Decoder(recvMsg[:n])
		assert.Nil(t, err)

		// Source RAN send ngap UE Context Release Complete
		// CountDown(10, "send UE Context Release Command Complete")
		// latency_info.msg = "Source RAN send out for 14(b). UE Context Release Command Complete"
		// latency_info.t_start = time.Now()
		pduSessionIDList := []int64{10}
		sendMsg, err = test.GetUEContextReleaseComplete(ue.AmfUeNgapId+int64(i), ue.RanUeNgapId, pduSessionIDList)
		assert.Nil(t, err)
		_, err = two_conn[now_connected].Write(sendMsg)
		// latency_info.t_end = time.Now()
		// latency_infos[latency_infos_idx] = latency_info
		// latency_infos_idx++
		assert.Nil(t, err)
		if err == nil {
			HandoverLogger.Infoln("Source RAN Send NGAP UE Context Release Complete")
		} else {
			HandoverLogger.Errorln("Source RAN Send NGAP UE Context Release Complete")
		}

		// CountDown(10, "UE Send NAS Registration Request(Mobility Registration Update) To Target AMF")
		// UE send NAS Registration Request(Mobility Registration Update) To Target AMF (2 AMF scenario not supportted yet)
		// latency_info.msg = "UE send NAS Registration Request To Target AMF"
		// latency_info.t_start = time.Now()
		mobileIdentity5GS = nasType.MobileIdentity5GS{
			Len:    11, // 5g-guti
			Buffer: []uint8{0x02, 0x02, 0xf8, 0x39, 0xca, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x01},
		}
		uplinkDataStatus := nasType.NewUplinkDataStatus(nasMessage.RegistrationRequestUplinkDataStatusType)
		uplinkDataStatus.SetLen(2)
		uplinkDataStatus.SetPSI10(1)
		ueSecurityCapability = targetUe.GetUESecurityCapability()
		pdu = nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSMobilityRegistrationUpdating,
			mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, uplinkDataStatus)
		pdu, err = test.EncodeNasPduWithSecurity(targetUe, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
		assert.Nil(t, err)
		sendMsg, err = test.GetInitialUEMessage(targetUe.RanUeNgapId, pdu, "")
		assert.Nil(t, err)
		_, err = two_conn[handover_to].Write(sendMsg)
		assert.Nil(t, err)
		if err == nil {
			HandoverLogger.Infoln("UE Send NAS Registration Request(Mobility Registration Update) To Target AMF")
		} else {
			HandoverLogger.Errorln("UE Send NAS Registration Request(Mobility Registration Update) To Target AMF")
		}

		// Target RAN receive ngap Initial Context Setup Request Msg
		// latency_info.msg = "Target RAN Wait for NGAP Initial Context Setup Request Msg"
		// latency_info.t_start = time.Now()
		n, err = two_conn[handover_to].Read(recvMsg)
		// latency_info.t_end = time.Now()
		// latency_infos[latency_infos_idx] = latency_info
		// latency_infos_idx++
		assert.Nil(t, err)
		if err == nil {
			HandoverLogger.Infoln("Target RAN Receive NGAP Initial Context Setup Request Msg")
		} else {
			HandoverLogger.Errorln("Target RAN Receive NGAP Initial Context Setup Request Msg")
		}
		_, err = ngap.Decoder(recvMsg[:n])
		assert.Nil(t, err)

		// Target RAN send ngap Initial Context Setup Response Msg
		sendMsg, err = test.GetInitialContextSetupResponseForServiceRequest(targetUe.AmfUeNgapId, targetUe.RanUeNgapId, "10.200.200.2")
		assert.Nil(t, err)
		_, err = two_conn[handover_to].Write(sendMsg)
		assert.Nil(t, err)
		if err == nil {
			HandoverLogger.Infoln("Target RAN Send NGAP Initial Context Setup Response Msg")
		} else {
			HandoverLogger.Errorln("Target RAN Send NGAP Initial Context Setup Response Msg")
		}

		// Target RAN send NAS Registration Complete Msg
		pdu = nasTestpacket.GetRegistrationComplete(nil)
		pdu, err = test.EncodeNasPduWithSecurity(targetUe, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
		assert.Nil(t, err)
		sendMsg, err = test.GetUplinkNASTransport(targetUe.AmfUeNgapId, targetUe.RanUeNgapId, pdu)
		assert.Nil(t, err)
		_, err = two_conn[handover_to].Write(sendMsg)
		assert.Nil(t, err)
		if err == nil {
			HandoverLogger.Infoln("Target RAN Send NAS Registration Complete Msg")
		} else {
			HandoverLogger.Errorln("Target RAN Send NAS Registration Complete Msg")
		}
		// latency_info.t_end = time.Now()
		// latency_infos[latency_infos_idx] = latency_info
		// latency_infos_idx++

		t6 := time.Now()
		HandoverLogger.Warnf("[Finish NGAP Handover]: %v (seconds)\n", t6.Sub(t5).Seconds())

		tmp := now_connected
		now_connected = handover_to
		handover_to = tmp
		ue = deepcopy.Copy(targetUe).(*test.RanUeContext)
		time.Sleep(1000 * time.Millisecond)
	}
	// for i := 0; i < latency_infos_idx; i++ {
	// 	fmt.Printf("Latency: %.9f\tMsg: %v\n", latency_infos[i].t_end.Sub(latency_infos[i].t_start).Seconds(), latency_infos[i].msg)
	// }

	// wait 1000 ms
	time.Sleep(1000 * time.Millisecond)

	// Send the dummy packet
	// ping IP(tunnel IP) from 60.60.0.2(127.0.0.1) to 60.60.0.20(127.0.0.8)
	//	_, err = upfConn2.Write(append(tt, b...))
	//	assert.Nil(t, err)

	time.Sleep(100 * time.Millisecond)

	// delete test data
	test.DelAuthSubscriptionToMongoDB(ue.Supi)
	test.DelAccessAndMobilitySubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)
	test.DelSmfSelectionSubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)

	// close Connection
	conn.Close()
	conn2.Close()

	// onvmpoller.CloseONVM()

	// terminate all NF
	//	NfTerminate()
}

func SingleN2Handover(idx int, data MobileIdentityGroup, t *testing.T, thread_amount int, x int) time.Duration {
	var n int
	var sendMsg []byte
	recvMsg := make([]byte, 2048)
	var err error
	var conn *sctp.SCTPConn
	var conn2 *sctp.SCTPConn
	timeout := new(syscall.Timeval)
	timeout.Sec = 10
	trigger_better_sleep := false

	// RAN1 connect to AMF
	for x := 0; x < 100; x++ {
		conn, err = test.ConnectToAmf(amfN2Ipv4Addr, ranN2Ipv4Addr, 38412, int(data.port))
		if err == nil {
			PagingLogger.Info("RAN connect to AMF")
			break
		} else {
			PagingLogger.Errorf("RAN connect to AMF, Error = %v, Port = %v", err.Error(), data.port)
		}
		time.Sleep(10 * time.Millisecond)
	}
	err = conn.SetWriteTimeout(*timeout)
	err = conn.SetReadTimeout(*timeout)

	// RAN1 send NGSetupRequest Msg
	ran_byte := []uint8{0x00, 0x01, 0x00}
	ran_byte[2] = uint8(2*idx - 1)
	sendMsg, err = test.GetNGSetupRequest(ran_byte, 24, "free5gc")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("RAN1 Send NGSetupRequest Msg")
	} else {
		HandoverLogger.Errorln("RAN1 Send NGSetupRequest Msg Error")
	}

	// RAN1 receive NGSetupResponse Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("RAN1 Receive NGSetupResponse Msg")
	} else {
		HandoverLogger.Errorln("RAN1 Receive NGSetupResponse Msg Error")
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	time.Sleep(10 * time.Millisecond)

	// RAN2 connect to AMF
	for x := 0; x < 100; x++ {
		conn2, err = test.ConnectToAmf(amfN2Ipv4Addr, ranN2Ipv4Addr, 38412, int(data.port+64))
		if err == nil {
			PagingLogger.Info("RAN connect to AMF")
			break
		} else {
			PagingLogger.Errorf("RAN connect to AMF, Error = %v, Port = %v", err.Error(), data.port)
		}
		time.Sleep(10 * time.Millisecond)
	}
	err = conn2.SetWriteTimeout(*timeout)
	err = conn2.SetReadTimeout(*timeout)
	ran_byte[2] = uint8(2 * idx)
	// RAN2 send Second NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest(ran_byte, 24, "nctu")
	assert.Nil(t, err)
	_, err = conn2.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("RAN2 Send Second NGSetupRequest Msg")
	} else {
		HandoverLogger.Errorln("RAN2 Send Second NGSetupRequest Msg")
	}

	// RAN2 receive Second NGSetupResponse Msg
	n, err = conn2.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("RAN2 Receive Second NGSetupResponse Msg")
	} else {
		HandoverLogger.Errorln("RAN2 Receive Second NGSetupResponse Msg")
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// New UE
	ue := test.NewRanUeContext(data.supi, 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2)
	ue.AmfUeNgapId = int64(idx)
	ue.RanUeNgapId = 1
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

	HandoverLogger.Warnln("[Start Registration]")
	t1 := time.Now()

	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("Send Initial UE Message")
	} else {
		HandoverLogger.Errorln("Send Initial UE Message")
	}

	// receive NAS Authentication Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("Receive NAS Authentication Request Msg")
	} else {
		HandoverLogger.Errorln("Receive NAS Authentication Request Msg")
	}
	ngapMsg, err := ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// Calculate for RES*
	nasPdu := test.GetNasPdu(ue, ngapMsg.InitiatingMessage.Value.DownlinkNASTransport)
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
		HandoverLogger.Infoln("Send NAS Authentication Response")
	} else {
		HandoverLogger.Errorln("Send NAS Authentication Response")
	}

	// receive NAS Security Mode Command Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("Receive NAS Security Mode Command Msg")
	} else {
		HandoverLogger.Errorln("Receive NAS Security Mode Command Msg")
	}
	ngapPdu, err := ngap.Decoder(recvMsg[:n])
	require.Nil(t, err)
	require.NotNil(t, ngapPdu)
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
		HandoverLogger.Infoln("Send NAS Security Mode Complete Msg")
	} else {
		HandoverLogger.Errorln("Send NAS Security Mode Complete Msg")
	}

	// receive ngap Initial Context Setup Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("Receive NGAP Initial Context Setup Request Msg")
	} else {
		HandoverLogger.Errorln("Receive NGAP Initial Context Setup Request Msg")
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("Send NGAP Initial Context Setup Response Msg")
	} else {
		HandoverLogger.Errorln("Send NGAP Initial Context Setup Response Msg")
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
		HandoverLogger.Infoln("Send NAS Registration Complete Msg")
	} else {
		HandoverLogger.Errorln("Send NAS Registration Complete Msg")
	}

	t2 := time.Now()
	HandoverLogger.Warnf("[Finish Registration]: %v (seconds)\n", t2.Sub(t1).Seconds())
	fmt.Println(idx, " [Finish Registration]")
	if trigger_better_sleep {
		// If sleep, latency of PDU session establishment will faster in both free5C and XIO-free5GC cases. But why?
		// Because this sleep will absorb the Step 22. and the following steps
		time.Sleep(1 * time.Second)
	}
	HandoverLogger.Warnln("[Start PDU Session Establishment]")
	pdu_session_establishment_latency, err := EstablishPduSession(t, conn, ue)
	HandoverLogger.Warnf("[Finish PDU Session Establishment]: %v (seconds)\n", pdu_session_establishment_latency.Seconds())
	fmt.Println(idx, " [Finish PDU Session Establishment]")
	time.Sleep(1 * time.Second)
	HandoverLogger.Infoln("End of Preparation phase")
	//fmt.Println("lock value: %d", LockForHandover.counter)
	LockForHandover.inc()
	for LockForHandover.counter < thread_amount {
		continue
	}
	//fmt.Println("lock value: %d", LockForHandover.counter)
	LockForHandover.block()
	// ============================================

	// Source RAN send ngap Handover Required Msg
	HandoverLogger.Warnln("[Start NGAP Handlover]")
	// time.Sleep(time.Second * 20)
	t5 := time.Now()

	// latency_info.msg = "Handover Preparation Phase"
	// latency_info.t_start = time.Now()
	// latency_info.msg = "Source RAN send out 1. Handover Required"
	// latency_info.t_start = time.Now()
	sendMsg, err = test.GetHandoverRequired(ue.AmfUeNgapId, ue.RanUeNgapId, ran_byte, []byte{0x01, 0x20})
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	// latency_info.t_end = time.Now()
	// latency_infos[latency_infos_idx] = latency_info
	// latency_infos_idx++
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("Source RAN Send NGAP Handover Required Msg")
	} else {
		HandoverLogger.Errorln("Source RAN Send NGAP Handover Required Msg")
	}
	// Target RAN receive ngap Handover Request
	// latency_info.msg = "Target RAN wait for 9. Handover Request"
	// latency_info.t_start = time.Now()
	n, err = conn2.Read(recvMsg)
	// latency_info.t_end = time.Now()
	// latency_infos[latency_infos_idx] = latency_info
	// latency_infos_idx++

	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("Target RAN Receive NGAP Handover Request")
	} else {
		HandoverLogger.Errorln("Target RAN Receive NGAP Handover Request")
	}
	//byte_to_int, _ := strconv.Atoi(string(recvMsg[76:78]))
	Handover_Request, err := ngap.Decoder(recvMsg[:n])
	TargetUeAmfUeNgapId := Handover_Request.InitiatingMessage.Value.HandoverRequest.ProtocolIEs.List[0].Value.AMFUENGAPID
	//fmt.Println("Target AmfUeNgapId is ", TargetUeAmfUeNgapId.Value)
	assert.Nil(t, err)

	// Target RAN create New UE
	// latency_info.msg = "DeepCopy UE to Target UE"
	// latency_info.t_start = time.Now()

	targetUe := deepcopy.Copy(ue).(*test.RanUeContext)
	//targetUe.AmfUeNgapId = int64(idx) + int64(thread_amount)
	targetUe.AmfUeNgapId = TargetUeAmfUeNgapId.Value
	targetUe.ULCount.Set(ue.ULCount.Overflow(), ue.ULCount.SQN())
	targetUe.DLCount.Set(ue.DLCount.Overflow(), ue.DLCount.SQN())
	// latency_info.t_end = time.Now()
	// latency_infos[latency_infos_idx] = latency_info
	// latency_infos_idx++

	// Target RAN send ngap Handover Request Acknowledge Msg
	sendMsg, err = test.GetHandoverRequestAcknowledge(targetUe.AmfUeNgapId, targetUe.RanUeNgapId)
	assert.Nil(t, err)
	// latency_info.msg = "Target RAN send out 10. Handover Request ACK"
	// latency_info.t_start = time.Now()
	_, err = conn2.Write(sendMsg)
	// latency_info.t_end = time.Now()
	// latency_infos[latency_infos_idx] = latency_info
	// latency_infos_idx++
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("Target RAN Send NGAP Handover Request Acknowledge Msg")
	} else {
		HandoverLogger.Errorln("Target RAN Send NGAP Handover Request Acknowledge Msg")
	}
	// latency_info.t_end = time.Now()
	// latency_infos[latency_infos_idx] = latency_info
	// latency_infos_idx++
	// End of Preparation phase
	// time.Sleep(10 * time.Millisecond)

	// Beginning of Execution

	// Source RAN receive ngap Handover Command
	// latency_info.msg = "Source RAN wait for 1. Handover Command"
	// latency_info.t_start = time.Now()
	n, err = conn.Read(recvMsg)
	// latency_info.t_end = time.Now()
	// latency_infos[latency_infos_idx] = latency_info
	// latency_infos_idx++
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("Source RAN Receive NGAP Handover Command")
	} else {
		HandoverLogger.Errorln("Source RAN Receive NGAP Handover Command")
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// Target RAN send ngap Handover Notify
	// CountDown(10, "send Handover Notify")
	if err != nil {
		HandoverLogger.Errorln(err.Error())
	}
	sendMsg, err = test.GetHandoverNotify(targetUe.AmfUeNgapId, targetUe.RanUeNgapId)
	assert.Nil(t, err)
	// latency_info.msg = "Target RAN send out 5. Handover Notify"
	// latency_info.t_start = time.Now()
	_, err = conn2.Write(sendMsg)
	// latency_info.t_end = time.Now()
	// latency_infos[latency_infos_idx] = latency_info
	// latency_infos_idx++
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("Target RAN Send NGAP Handover Notify")
	} else {
		HandoverLogger.Errorln("Target RAN Send NGAP Handover Notify")
	}

	// Source RAN receive ngap UE Context Release Command
	// latency_info.msg = "Source RAN wait for 14(a). UE Context Release Command"
	// latency_info.t_start = time.Now()
	n, err = conn.Read(recvMsg)
	// latency_info.t_end = time.Now()
	// latency_infos[latency_infos_idx] = latency_info
	// latency_infos_idx++
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("Source RAN Receive NGAP UE Context Release Command")
	} else {
		HandoverLogger.Errorln("Source RAN Receive NGAP UE Context Release Command")
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// Source RAN send ngap UE Context Release Complete
	// CountDown(10, "send UE Context Release Command Complete")
	// latency_info.msg = "Source RAN send out for 14(b). UE Context Release Command Complete"
	// latency_info.t_start = time.Now()
	pduSessionIDList := []int64{10}
	sendMsg, err = test.GetUEContextReleaseComplete(ue.AmfUeNgapId, ue.RanUeNgapId, pduSessionIDList)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	// latency_info.t_end = time.Now()
	// latency_infos[latency_infos_idx] = latency_info
	// latency_infos_idx++
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("Source RAN Send NGAP UE Context Release Complete")
	} else {
		HandoverLogger.Errorln("Source RAN Send NGAP UE Context Release Complete")
	}

	// CountDown(10, "UE Send NAS Registration Request(Mobility Registration Update) To Target AMF")
	// UE send NAS Registration Request(Mobility Registration Update) To Target AMF (2 AMF scenario not supportted yet)
	// latency_info.msg = "UE send NAS Registration Request To Target AMF"
	// latency_info.t_start = time.Now()
	// mobileIdentity5GS = nasType.MobileIdentity5GS{
	// 	Len:    11, // 5g-guti
	// 	Buffer: []uint8{0x02, 0x02, 0xf8, 0x39, 0xca, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x01},
	// }
	//fmt.Println(mobileIdentity5GS.Buffer)
	// mobileIdentity5GS = nasType.MobileIdentity5GS{
	// 	Len:    11, // 5g-guti
	// 	Buffer: []uint8(mobileIdentity5GS.Get5GGUTI()),
	// }
	mobileIdentity5GS.Buffer = mobileIdentity5GS.Buffer[:11]
	mobileIdentity5GS.Buffer[0] = uint8(2)
	mobileIdentity5GS.Buffer[4] = uint8(0xca)
	mobileIdentity5GS.Buffer[5] = uint8(0xfe)
	//idx_b := idx % 16
	mobileIdentity5GS.Buffer[10] = uint8(idx)
	mobileIdentity5GS.Len = 11
	//fmt.Println(mobileIdentity5GS.Buffer)
	uplinkDataStatus := nasType.NewUplinkDataStatus(nasMessage.RegistrationRequestUplinkDataStatusType)
	uplinkDataStatus.SetLen(2)
	uplinkDataStatus.SetPSI10(1)
	ueSecurityCapability = targetUe.GetUESecurityCapability()
	pdu = nasTestpacket.GetRegistrationRequest(nasMessage.RegistrationType5GSMobilityRegistrationUpdating,
		mobileIdentity5GS, nil, ueSecurityCapability, ue.Get5GMMCapability(), nil, uplinkDataStatus)
	pdu, err = test.EncodeNasPduWithSecurity(targetUe, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(targetUe.AmfUeNgapId, targetUe.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn2.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("UE Send NAS Registration Request(Mobility Registration Update) To Target AMF")
	} else {
		HandoverLogger.Errorln("UE Send NAS Registration Request(Mobility Registration Update) To Target AMF")
	}

	// Target RAN receive ngap Initial Context Setup Request Msg
	// latency_info.msg = "Target RAN Wait for NGAP Initial Context Setup Request Msg"
	// latency_info.t_start = time.Now()
	n, err = conn2.Read(recvMsg)
	// latency_info.t_end = time.Now()
	// latency_infos[latency_infos_idx] = latency_info
	// latency_infos_idx++
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("Target RAN Receive NGAP Initial Context Setup Request Msg")
	} else {
		HandoverLogger.Errorln("Target RAN Receive NGAP Initial Context Setup Request Msg")
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// Target RAN send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetPDUSessionResourceSetupResponseForPaging(targetUe.AmfUeNgapId, targetUe.RanUeNgapId, "10.200.200.2")
	assert.Nil(t, err)
	_, err = conn2.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("Target RAN Send NGAP Initial Context Setup Response Msg")
	} else {
		HandoverLogger.Errorln("Target RAN Send NGAP Initial Context Setup Response Msg")
	}

	// Target RAN send NAS Registration Complete Msg
	pdu = nasTestpacket.GetRegistrationComplete(nil)
	pdu, err = test.EncodeNasPduWithSecurity(targetUe, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetUplinkNASTransport(targetUe.AmfUeNgapId, targetUe.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn2.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		HandoverLogger.Infoln("Target RAN Send NAS Registration Complete Msg")
	} else {
		HandoverLogger.Errorln("Target RAN Send NAS Registration Complete Msg")
	}
	// latency_info.t_end = time.Now()
	// latency_infos[latency_infos_idx] = latency_info
	// latency_infos_idx++
	t6 := time.Now()
	handover_latency := t6.Sub(t5)

	HandoverLogger.Warnf("[Finish NGAP Handover]: %v (seconds)\n", handover_latency.Seconds())

	// for i := 0; i < latency_infos_idx; i++ {
	// 	fmt.Printf("Latency: %.9f\tMsg: %v\n", latency_infos[i].t_end.Sub(latency_infos[i].t_start).Seconds(), latency_infos[i].msg)
	// }

	// wait 1000 ms
	defer LockForHandover.dec()

	// Send the dummy packet
	// ping IP(tunnel IP) from 60.60.0.2(127.0.0.1) to 60.60.0.20(127.0.0.8)
	//	_, err = upfConn2.Write(append(tt, b...))
	//	assert.Nil(t, err)

	// delete test data
	test.DelAuthSubscriptionToMongoDB(ue.Supi)
	test.DelAccessAndMobilitySubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)
	test.DelSmfSelectionSubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)
	test.DelAuthSubscriptionToMongoDB(targetUe.Supi)
	test.DelAccessAndMobilitySubscriptionDataFromMongoDB(targetUe.Supi, servingPlmnId)
	test.DelSmfSelectionSubscriptionDataFromMongoDB(targetUe.Supi, servingPlmnId)
	time.Sleep(1 * time.Second)
	// close Connection
	conn.Close()
	conn2.Close()
	return handover_latency
}

func HandoverWorker(name string, wg *sync.WaitGroup, work_data_array []WorkData, handover_latency_chan chan time.Duration, t *testing.T, thread_amount int, x int) {
	// fmt.Println(name, "start")
	for _, work_data := range work_data_array {
		// fmt.Println(name, "handle id", work_data.id)
		handover_latency := SingleN2Handover(work_data.id+1, work_data.mobile_identiy_group, t, thread_amount, x)
		handover_latency_chan <- handover_latency
	}
	wg.Done()
	fmt.Println(name, "done")
}


func TestMultiN2HandoverConcurrent(t *testing.T) {
	SetLogLevel(logrus.ErrorLevel)

	thread_amount, err := StringToInteger(os.Args[6])
	if err != nil {
        t.Errorf("Invalid thread_amount: %s", err)
        return
    }
	const work_load int = 1
	amount  := thread_amount * work_load // 16 * 1
	LockForHandover.counter = 0
	//fmt.Println([]uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10})
	//fmt.Println([]uint8{0x02, 0x02, 0xf8, 0x39, 0xca, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x01})
	mobile_identiy_groups := GenerateMobileIdentityGroup()[:amount]
	work_data_array := make([]WorkData, amount)
	wg := new(sync.WaitGroup)
	handover_latency_chan := make(chan time.Duration, amount+1)

	onvmpoller.SetLocalAddress(testUsedIpAddr)
	go FileLogger("handover.txt", handover_latency_chan)

	for x := 0; x < amount; x++ {
		work_data_array[x] = WorkData{
			id:                   x,
			mobile_identiy_group: mobile_identiy_groups[x],
		}
	}

	wg.Add(thread_amount)
	for x := 0; x < thread_amount; x++ {
		name := fmt.Sprintf("Worker%d", x+1)
		// fmt.Println("From", work_data_array[x*work_load].id, "To", work_data_array[x*work_load+(work_load-1)].id)
		go HandoverWorker(name, wg, work_data_array[x*work_load:x*work_load+(work_load)], handover_latency_chan, t, thread_amount, x)
		time.Sleep(500 * time.Millisecond)
	}
	wg.Wait()

	close(handover_latency_chan)
	time.Sleep(2 * time.Second) // Let FileLogger have encough time to write data
	fmt.Println("MultiPagingConcurrent Done")
}