package test_test

import (
	"fmt"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"

	"test"

	"git.cs.nctu.edu.tw/calee/sctp"
	"github.com/nycu-ucr/CommonConsumerTestData/UDM/TestGenAuthData"
	"github.com/nycu-ucr/nas"
	"github.com/nycu-ucr/nas/nasMessage"
	"github.com/nycu-ucr/nas/nasTestpacket"
	"github.com/nycu-ucr/nas/nasType"
	"github.com/nycu-ucr/nas/security"
	"github.com/nycu-ucr/ngap"
	"github.com/nycu-ucr/ngap/ngapType"
	"github.com/nycu-ucr/onvmpoller"
	"github.com/nycu-ucr/openapi/models"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)


// Registration -> Pdu Session Establishment -> AN Release due to UE Idle -> Send downlink data
func TestPaging(t *testing.T) {
	var n int
	var sendMsg []byte
	recvMsg := make([]byte, 2048)

	onvmpoller.SetLocalAddress(testUsedIpAddr)

	// RAN connect to AMF
	//conn, err := test.ConnectToAmf(ranN2Ipv4Addr, amfN2Ipv4Addr, 38412, 9487)
	conn, err := test.ConnectToAmf(amfN2Ipv4Addr, ranN2Ipv4Addr, 38412, 9487)
	assert.Nil(t, err)
	if err == nil {
		PagingLogger.Info("RAN connect to AMF")
	} else {
		PagingLogger.Error("RAN connect to AMF")
	}

	// send NGSetupRequest Msg
	sendMsg, err = test.GetNGSetupRequest([]byte("\x00\x01\x02"), 24, "free5gc")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		PagingLogger.Info("Send NGSetupRequest Msg")
	} else {
		PagingLogger.Error("Send NGSetupRequest Msg")
	}

	// receive NGSetupResponse Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		PagingLogger.Info("Receive NGSetupResponse Msg")
	} else {
		PagingLogger.Error("Receive NGSetupResponse Msg")
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// New UE
	ue := test.NewRanUeContext("imsi-2089300007487", 1, security.AlgCiphering128NEA0, security.AlgIntegrity128NIA2)
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
		Len:    12, // suci
		Buffer: []uint8{0x01, 0x02, 0xf8, 0x39, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x47, 0x78},
	}
	ueSecurityCapability := ue.GetUESecurityCapability()
	registrationRequest := nasTestpacket.GetRegistrationRequest(
		nasMessage.RegistrationType5GSInitialRegistration, mobileIdentity5GS, nil, ueSecurityCapability, nil, nil, nil)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, registrationRequest, "")
	assert.Nil(t, err)

	PagingLogger.Warnln("[Start Registration]")
	t1 := time.Now()

	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		PagingLogger.Info("Send Initial UE Message")
	} else {
		PagingLogger.Error("Send Initial UE Message")
	}

	// receive NAS Authentication Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		PagingLogger.Info("Receive NAS Authentication Request Msg")
	} else {
		PagingLogger.Error("Receive NAS Authentication Request Msg")
	}
	ngapPdu, err := ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	amfUeNgapId := test.GetAmfUeNgapId(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	if amfUeNgapId == nil {
		PagingLogger.Errorln("amfUeNgapId is nil")
	} else {
		ue.AmfUeNgapId = amfUeNgapId.Value
	}
	PagingLogger.Infof("(Conn, AmfUeNgapId, RanUeNgapId) = (%v, %v, %v)", conn.LocalAddr(), ue.AmfUeNgapId, ue.RanUeNgapId)

	// Calculate for RES*
	nasPdu := test.GetNasPdu(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	assert.NotNil(t, nasPdu)
	rand := nasPdu.AuthenticationRequest.GetRANDValue()
	resStat := ue.DeriveRESstarAndSetKey(ue.AuthenticationSubs, rand[:], "5G:mnc093.mcc208.3gppnetwork.org")

	// send NAS Authentication Response
	pdu := nasTestpacket.GetAuthenticationResponse(resStat, "")
	sendMsg, err = test.GetUplinkNASTransport(ue.AmfUeNgapId, ue.RanUeNgapId, pdu)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		PagingLogger.Info("Send NAS Authentication Response")
	} else {
		PagingLogger.Error("Send NAS Authentication Response")
	}

	// receive NAS Security Mode Command Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		PagingLogger.Info("Receive NAS Security Mode Command Msg")
	} else {
		PagingLogger.Error("Receive NAS Security Mode Command Msg")
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

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
		PagingLogger.Info("Send NAS Security Mode Complete Msg")
	} else {
		PagingLogger.Error("Send NAS Security Mode Complete Msg")
	}

	// receive ngap Initial Context Setup Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		PagingLogger.Info("Receive NGAP Initial Context Setup Request Msg")
	} else {
		PagingLogger.Error("Receive NGAP Initial Context Setup Request Msg")
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		PagingLogger.Info("Send NGAP Initial Context Setup Response Msg")
	} else {
		PagingLogger.Error("Send NGAP Initial Context Setup Response Msg")
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
		PagingLogger.Info("Send NAS Registration Complete Msg")
	} else {
		PagingLogger.Error("Send NAS Registration Complete Msg")
	}

	t2 := time.Now()
	PagingLogger.Warnf("[Finish Registration]: %v (seconds)\n", t2.Sub(t1).Seconds())

	PagingLogger.Warnf("[Start PDU Session Establishment]")
	t3 := time.Now()

	// send PduSessionEstablishmentRequest Msg
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
		PagingLogger.Info("Send PduSessionEstablishmentRequest Msg")
	} else {
		PagingLogger.Error("Send PduSessionEstablishmentRequest Msg")
	}

	// receive 12. NGAP-PDU Session Resource Setup Request(DL nas transport((NAS msg-PDU session setup Accept)))
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		PagingLogger.Info("Receive NGAP-PDU Session Resource Setup Request")
	} else {
		PagingLogger.Error("Receive NGAP-PDU Session Resource Setup Request")
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send 14. NGAP-PDU Session Resource Setup Response
	sendMsg, err = test.GetPDUSessionResourceSetupResponse(10, ue.AmfUeNgapId, ue.RanUeNgapId, ranN3Ipv4Addr)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		PagingLogger.Info("Send NGAP-PDU Session Resource Setup Response")
	} else {
		PagingLogger.Error("Send NGAP-PDU Session Resource Setup Response")
	}

	t4 := time.Now()
	PagingLogger.Warnf("[Finish PDU Session Establishment]: %v (seconds)\n", t4.Sub(t3).Seconds())

	// send ngap UE Context Release Request
	pduSessionIDList := []int64{10}
	sendMsg, err = test.GetUEContextReleaseRequest(ue.AmfUeNgapId, ue.RanUeNgapId, pduSessionIDList)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		PagingLogger.Info("Send NGAP UE Context Release Request")
	} else {
		PagingLogger.Error("Send NGAP UE Context Release Request")
	}

	// receive UE Context Release Command
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		PagingLogger.Info("Receive UE Context Release Command")
	} else {
		PagingLogger.Error("Receive UE Context Release Command")
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send ngap UE Context Release Complete
	sendMsg, err = test.GetUEContextReleaseComplete(ue.AmfUeNgapId, ue.RanUeNgapId, nil)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		PagingLogger.Info("Send NGAP UE Context Release Complete")
	} else {
		PagingLogger.Error("Send NGAP UE Context Release Complete")
	}

	// UE is CM-IDLE now
	PagingLogger.Warnln("[UE IS CM-IDLE NOW]")
	// time.Sleep(1 * time.Second)
	PagingLogger.Warnln("[Instruct DN To Send Downlink Traffic]")

	// send downlink data
	/* free5GC version with 1 host
	 * If it can't work, directly use "ping 60.60.0.1 -I upfgtp -c 1"
	 */
	 go func() {
		// RAN connect to UPF
		upfConn, err := test.ConnectToUpf(ranN3Ipv4Addr, "127.0.0.8", 2152, 2152)
		assert.Nil(t, err)
		_, _ = upfConn.Read(recvMsg)
		// fmt.Println(string(recvMsg))
	}()

	exec_type := os.Getenv("PAGING_TYPE")
	if exec_type == "free5GC" {
		go func() {
			//cmd := exec.Command("ping", "10.60.0.1", "-I", "UPFns", "-c", "1")
			cmd := exec.Command("sudo", "ip", "netns", "exec", "UPFns", "bash", "-c", "echo -n 'hello' | nc -u -w1 10.60.0.1 8080")
			cmd.Run()
		}()
	} else if exec_type == "L25GC" {
		/* L25GC version with 3 host */
		cmd := exec.Command("python3", "./python_paging_client.py")
		_, err = cmd.Output()
		if err != nil {
			PagingLogger.Errorf("Instruct DN to send downlink traffic Error: %v\n", err)
			assert.Nil(t, err)
		}
	} else if exec_type == "XIO-free5GC" {
		/* XIO-L25GC version with 1 host */
		onvmpoller.TriggerPaging(upfServiceId, testUsedIpAddr, "10.60.0.1")
	} else {
		PagingLogger.Errorln("Please set env variable 'PAGING_TYPE' to 'free5GC' or 'L25GC' or 'XIO-free5GC'")
		require.NotEqual(t, "", exec_type)
	}

	// send downlink data done

	// time.Sleep(1 * time.Second)

	PagingLogger.Warnln("[Waiting To Receive Paing From AMF]")
	// receive paing from AMF
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		PagingLogger.Info("Receive paing from AMF")
	} else {
		PagingLogger.Error("Receive paing from AMF")
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	PagingLogger.Warnln("[Start Paging]")
	t5 := time.Now()

	// send NAS Service Request
	ue.AmfUeNgapId = 2
	pdu = nasTestpacket.GetServiceRequest(nasMessage.ServiceTypeMobileTerminatedServices)
//	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtectedAndCiphered, true, false)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtected, true, false)
	assert.Nil(t, err)
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, pdu, "fe0000000001")
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		PagingLogger.Info("Send NAS Service Request")
	} else {
		PagingLogger.Error("Send NAS Service Request")
	}

	// receive Initial Context Setup Request
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		PagingLogger.Info("Receive Initial Context Setup Request")
	} else {
		PagingLogger.Error("Receive Initial Context Setup Request")
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send Initial Context Setup Response
	sendMsg, err = test.GetInitialContextSetupResponseForServiceRequest(ue.AmfUeNgapId, ue.RanUeNgapId, ranN3Ipv4Addr)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		PagingLogger.Info("Send Initial Context Setup Response")
	} else {
		PagingLogger.Error("Send Initial Context Setup Response")
	}

	t6 := time.Now()
	PagingLogger.Warnf("[Finish Paging]: %v (seconds)\n", t6.Sub(t5).Seconds())

	// delete test data
	test.DelAuthSubscriptionToMongoDB(ue.Supi)
	test.DelAccessAndMobilitySubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)
	test.DelSmfSelectionSubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)

	// close Connection
	conn.Close()
}

func SinglePaging(idx int, data MobileIdentityGroup, signal_chan chan string, t *testing.T) time.Duration {
	var n int
	var sendMsg []byte
	recvMsg := make([]byte, 2048)
	var err error
	var conn *sctp.SCTPConn

	// RAN connect to AMF
	for x := 0; x < 10; x++ {
		conn, err = test.ConnectToAmf(amfN2Ipv4Addr, ranN2Ipv4Addr, 38412, int(data.port))
		if err == nil {
			PagingLogger.Info("RAN connect to AMF")
			break
		} else {
			PagingLogger.Errorf("RAN connect to AMF, Error = %v, Port = %v", err.Error(), data.port)
		}
		time.Sleep(10 * time.Millisecond)
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
		PagingLogger.Info("Send NGSetupRequest Msg")
	} else {
		PagingLogger.Error("Send NGSetupRequest Msg")
	}

	// receive NGSetupResponse Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		PagingLogger.Info("Receive NGSetupResponse Msg")
	} else {
		PagingLogger.Error("Receive NGSetupResponse Msg")
	}
	ngapPdu, err := ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentSuccessfulOutcome && ngapPdu.SuccessfulOutcome.ProcedureCode.Value == ngapType.ProcedureCodeNGSetup, "No NGSetupResponse received.")

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

	PagingLogger.Warnln("[Start Registration]")
	t1 := time.Now()

	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		PagingLogger.Info("Send Initial UE Message")
	} else {
		PagingLogger.Error("Send Initial UE Message")
	}

	// receive NAS Authentication Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		PagingLogger.Info("Receive NAS Authentication Request Msg")
	} else {
		PagingLogger.Error("Receive NAS Authentication Request Msg")
	}
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage, "No NGAP Initiating Message received.")

	amfUeNgapId := test.GetAmfUeNgapId(ue, ngapPdu.InitiatingMessage.Value.DownlinkNASTransport)
	if amfUeNgapId == nil {
		PagingLogger.Errorln("amfUeNgapId is nil")
	} else {
		ue.AmfUeNgapId = amfUeNgapId.Value
	}
	PagingLogger.Infof("(Conn, AmfUeNgapId, RanUeNgapId) = (%v, %v, %v)", conn.LocalAddr(), ue.AmfUeNgapId, ue.RanUeNgapId)

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
		PagingLogger.Info("Send NAS Authentication Response")
	} else {
		PagingLogger.Error("Send NAS Authentication Response")
	}

	// receive NAS Security Mode Command Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		PagingLogger.Info("Receive NAS Security Mode Command Msg")
	} else {
		PagingLogger.Errorf("Receive NAS Security Mode Command Msg, error: %v", err)
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
		PagingLogger.Info("Send NAS Security Mode Complete Msg")
	} else {
		PagingLogger.Error("Send NAS Security Mode Complete Msg")
	}

	// receive ngap Initial Context Setup Request Msg
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		PagingLogger.Info("Receive NGAP Initial Context Setup Request Msg")
	} else {
		PagingLogger.Error("Receive NGAP Initial Context Setup Request Msg")
	}
	ngapPdu, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)
	assert.True(t, ngapPdu.Present == ngapType.NGAPPDUPresentInitiatingMessage &&
		ngapPdu.InitiatingMessage.ProcedureCode.Value == ngapType.ProcedureCodeInitialContextSetup,
		"No InitialContextSetup received.")
	tmsi, err := test.GetTmsiFromInitialContextSetupRequest(ue, ngapPdu.InitiatingMessage.Value.InitialContextSetupRequest)
	assert.Nil(t, err)
	PagingLogger.Debugf("TMSI = %v", tmsi)
	ue.Tmsi = tmsi

	// send ngap Initial Context Setup Response Msg
	sendMsg, err = test.GetInitialContextSetupResponse(ue.AmfUeNgapId, ue.RanUeNgapId)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		PagingLogger.Info("Send NGAP Initial Context Setup Response Msg")
	} else {
		PagingLogger.Error("Send NGAP Initial Context Setup Response Msg")
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
		PagingLogger.Info("Send NAS Registration Complete Msg")
	} else {
		PagingLogger.Error("Send NAS Registration Complete Msg")
	}

	t2 := time.Now()
	registration_latency := t2.Sub(t1)
	PagingLogger.Warnf("[Finish Registration]: %.9f (seconds)", registration_latency.Seconds())
	time.Sleep(time.Second * 1) // Let CN handle Registration Complete
	var pdu_session_establishment_latency time.Duration

	PagingLogger.Warnln("[Start PDU Session Establishment]")
	for i := 0; i < 1; i++ {
		pdu_session_establishment_latency, err = EstablishPduSession(t, conn, ue)
		if err == nil {
			break
		}
	}
	PagingLogger.Warnf("[Finish PDU Session Establishment]: %.9f (seconds)", pdu_session_establishment_latency.Seconds())
	PagingLogger.Infof("Address is %v\n", ue.PduAddress)

	// send ngap UE Context Release Request
	pduSessionIDList := []int64{10}
	sendMsg, err = test.GetUEContextReleaseRequest(ue.AmfUeNgapId, ue.RanUeNgapId, pduSessionIDList)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		PagingLogger.Info("Send NGAP UE Context Release Request")
	} else {
		PagingLogger.Error("Send NGAP UE Context Release Request")
	}

	// receive UE Context Release Command
	n, err = conn.Read(recvMsg)
	assert.Nil(t, err)
	if err == nil {
		PagingLogger.Info("Receive UE Context Release Command")
	} else {
		PagingLogger.Error("Receive UE Context Release Command")
	}
	_, err = ngap.Decoder(recvMsg[:n])
	assert.Nil(t, err)

	// send ngap UE Context Release Complete
	sendMsg, err = test.GetUEContextReleaseComplete(ue.AmfUeNgapId, ue.RanUeNgapId, nil)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		PagingLogger.Info("Send NGAP UE Context Release Complete")
	} else {
		PagingLogger.Error("Send NGAP UE Context Release Complete")
	}

	// UE is CM-IDLE now
	PagingLogger.Warnln("[UE IS CM-IDLE NOW]")
	// time.Sleep(1 * time.Second)
	PagingLogger.Warnln("[Instruct DN To Send Downlink Traffic]")

	// send downlink data
	/* free5GC version with 1 host
	 * If it can't work, directly use "ping 60.60.0.1 -I upfgtp -c 1"
	 */

	// TODO: Let itself send downlik packet
	// exec_type := os.Getenv("PAGING_TYPE")
	// if exec_type == "free5GC" {
	// 	go func() {
	// 		cmd := exec.Command("ping", ue.PduAddress, "-I", "upfgtp", "-c", "1")
	// 		cmd.Run()
	// 	}()
	// } else if exec_type == "L25GC" {
	// 	/* L25GC version with 3 host */
	// 	cmd := exec.Command("python3", "./python_paging_client.py")
	// 	_, err = cmd.Output()
	// 	if err != nil {
	// 		PagingLogger.Errorf("Instruct DN to send downlink traffic Error: %v\n", err)
	// 		assert.Nil(t, err)
	// 	}
	// } else if exec_type == "XIO-free5GC" {
	// 	/* XIO-L25GC version with 1 host */
	// 	onvmpoller.TriggerPaging(upfServiceId, testUsedIpAddr, ue.PduAddress)
	// } else {
	// 	PagingLogger.Errorln("Please set env variable 'PAGING_TYPE' to 'free5GC' or 'L25GC' or 'XIO-free5GC'")
	// 	require.NotEqual(t, "", exec_type)
	// }
	signal_chan <- ue.PduAddress

	// send downlink data done

	// time.Sleep(1 * time.Second)

	PagingLogger.Warnln("[Waiting To Receive Paing From AMF]")
	for {
		// receive paing from AMF
		n, err = conn.Read(recvMsg)
		assert.Nil(t, err)
		ngapPdu, err = ngap.Decoder(recvMsg[:n])
		assert.Nil(t, err)
		who, err := test.GetTmsiFromPaging(ue, ngapPdu.InitiatingMessage.Value.Paging)
		assert.Nil(t, err)
		PagingLogger.Tracef("(%v) CN send paing to %v\n", ue.Tmsi, who)
		if who == ue.Tmsi {
			PagingLogger.Infof("Receive Paing From AMF (%v)\n", ue.Tmsi)
			break
		}
	}

	PagingLogger.Warnln("[Start Paging]")
	t5 := time.Now()

	// send NAS Service Request
	pdu = nasTestpacket.GetServiceRequest(nasMessage.ServiceTypeMobileTerminatedServices)
	pdu, err = test.EncodeNasPduWithSecurity(ue, pdu, nas.SecurityHeaderTypeIntegrityProtected, true, false)
	assert.Nil(t, err)
	// sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, pdu, "fe0000000001")
	sendMsg, err = test.GetInitialUEMessage(ue.RanUeNgapId, pdu, ue.Tmsi)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		PagingLogger.Info("Send NAS Service Request")
	} else {
		PagingLogger.Error("Send NAS Service Request")
	}
	paging_latency := time.Second
	// Absorb other paging message
	for {
		// receive Initial Context Setup Request
		n, err = conn.Read(recvMsg)
		assert.Nil(t, err)
		if err == nil {
			PagingLogger.Info("Receive Initial Context Setup Request")
		} else {
			PagingLogger.Error("Receive Initial Context Setup Request")
		}
		ngapPdu, err = ngap.Decoder(recvMsg[:n])
		assert.Nil(t, err)
		if int64(ngapPdu.InitiatingMessage.ProcedureCode.Value) == ngapType.ProcedureCodeInitialContextSetup {

			break
		}
	}
	// send Initial Context Setup Response
	sendMsg, err = test.GetInitialContextSetupResponseForServiceRequest(ue.AmfUeNgapId, ue.RanUeNgapId, ranN3Ipv4Addr)
	assert.Nil(t, err)
	_, err = conn.Write(sendMsg)
	assert.Nil(t, err)
	if err == nil {
		PagingLogger.Info("Send Initial Context Setup Response")
	} else {
		PagingLogger.Error("Send Initial Context Setup Response")
	}
	t6 := time.Now()
	paging_latency = t6.Sub(t5)

	PagingLogger.Warnf("[Finish Paging]: %v (seconds)\n", paging_latency.Seconds())

	// delete test data
	test.DelAuthSubscriptionToMongoDB(ue.Supi)
	test.DelAccessAndMobilitySubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)
	test.DelSmfSelectionSubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)
	
	// close Connection
	conn.Close()
	return paging_latency
}

func PagingWorker(name string, wg *sync.WaitGroup, work_data_array []WorkData, paging_latency_chan chan time.Duration, signal_chan chan string, t *testing.T) {
	// fmt.Println(name, "start")
	for _, work_data := range work_data_array {
		// fmt.Println(name, "handle id", work_data.id)
		paging_latency := SinglePaging(work_data.id+1, work_data.mobile_identiy_group, signal_chan, t)
		paging_latency_chan <- paging_latency
		time.Sleep(500 * time.Millisecond)
	}
	wg.Done()
	fmt.Println(name, "done")
}

func DownlinkDataController(signal_chan chan string, thread_amount int) {
	counter := 0
	addressList := make([]string, thread_amount)
	for address := range signal_chan {
		if address != "" {
			addressList[counter] = address
			counter++
			if counter == thread_amount {
				PagingLogger.Infoln("Start send downlink packet")
				counter = 0

				for i := 0; i < thread_amount; i++ {
					PagingLogger.Infoln("Send to ", addressList[i])
					// free5GC
					cmd := exec.Command("ping", addressList[i], "-I", "upfgtp", "-c", "1")
					cmd.Start()
					// XIO-free5GC
					//onvmpoller.TriggerPaging(upfServiceId, testUsedIpAddr, addressList[i])
				}
			}
		}
	}
}

// func StringToInteger(str string) (int, error) {
//     intValue, err := strconv.Atoi(str)
//     if err != nil {
//         return 0, err
//     }
//     return intValue, nil
// }

func TestMultiPagingConcurrent(t *testing.T) {
	SetLogLevel(logrus.InfoLevel)

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
	amount  := thread_amount * work_load

	mobile_identiy_groups := GenerateMobileIdentityGroup()[:amount]
	work_data_array := make([]WorkData, amount)
	wg := new(sync.WaitGroup)
	paging_latency_chan := make(chan time.Duration, amount+1)
	dl_signal_chan := make(chan string, thread_amount+1)

	onvmpoller.SetLocalAddress(testUsedIpAddr)
	go FileLogger("paging_latency.txt", paging_latency_chan)
	go DownlinkDataController(dl_signal_chan, thread_amount)

	for x := 0; x < amount; x++ {
		work_data_array[x] = WorkData{
			id:                   x,
			mobile_identiy_group: mobile_identiy_groups[x],
		}
	}

	wg.Add(thread_amount)
	for x := 0; x < thread_amount; x++ {
		name := fmt.Sprintf("Worker%d", x)
		// fmt.Println("From", work_data_array[x*work_load].id, "To", work_data_array[x*work_load+(work_load-1)].id)
		go PagingWorker(name, wg, work_data_array[x*work_load:x*work_load+(work_load)], paging_latency_chan, dl_signal_chan, t)
		// time.Sleep(500 * time.Millisecond)
	}
	wg.Wait()

	close(paging_latency_chan)
	time.Sleep(2 * time.Second) // Let FileLogger have encough time to write data
	fmt.Println("MultiPagingConcurrent Done")
}
func TestTriggerPaging(t *testing.T) {
	onvmpoller.SetLocalAddress(testUsedIpAddr)
	onvmpoller.TriggerPaging(upfServiceId, testUsedIpAddr, "60.60.0.1")
}
