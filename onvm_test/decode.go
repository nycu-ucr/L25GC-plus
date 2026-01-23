package test

import (
	"fmt"
	"strconv"

	"github.com/nycu-ucr/nas"
	"github.com/nycu-ucr/ngap/ngapType"
)

func GetNasPdu(ue *RanUeContext, msg *ngapType.DownlinkNASTransport) (m *nas.Message) {
	for _, ie := range msg.ProtocolIEs.List {
		if ie.Id.Value == ngapType.ProtocolIEIDNASPDU {
			pkg := []byte(ie.Value.NASPDU.Value)
			m, err := NASDecode(ue, nas.GetSecurityHeaderType(pkg), pkg)
			if err != nil {
				return nil
			}
			return m
		}
	}
	return nil
}

func GetAmfUeNgapId(ue *RanUeContext, msg *ngapType.DownlinkNASTransport) (m *ngapType.AMFUENGAPID) {
	for _, ie := range msg.ProtocolIEs.List {
		if ie.Id.Value == ngapType.ProtocolIEIDAMFUENGAPID {
			return ie.Value.AMFUENGAPID
		}
	}
	return nil
}

func GetTmsiFromInitialContextSetupRequest(
	ue *RanUeContext, msg *ngapType.InitialContextSetupRequest,
) (sTmsi string, err error) {
	for _, ie := range msg.ProtocolIEs.List {
		if ie.Id.Value == ngapType.ProtocolIEIDNASPDU {
			pkg := []byte(ie.Value.NASPDU.Value)
			m, err := NASDecode(ue, nas.GetSecurityHeaderType(pkg), pkg)
			if err != nil {
				return "", err
			}
			guti := m.GmmMessage.RegistrationAccept.GUTI5G
			tmsiRaw := guti.GetTMSI5G()
			// amfSetId := guti.GetAMFSetID()
			amfSetId := "fe"
			// amfPtr := guti.GetAMFPointer()
			// fmt.Printf("amfSetId: %v\n", amfSetId)
			// fmt.Printf("amfPtr: %v\n", amfPtr)
			// fmt.Printf("tmsi_b: %v\n", tmsiRaw)
			tmsi := 0
			for idx, val := range tmsiRaw {
				tmsi += int(val)
				if idx != len(tmsiRaw)-1 {
					tmsi <<= 1
				}

			}
			// TODO: modify this
			sTmsi = fmt.Sprintf("%s%010x", amfSetId, tmsi)
		}
	}

	return
}

func GetTmsiFromPaging(
	ue *RanUeContext, msg *ngapType.Paging,
) (sTmsi string, err error) {
	if msg == nil {
		return "", fmt.Errorf("Msg is nil")
	}
	for _, ie := range msg.ProtocolIEs.List {
		if ie.Id.Value == ngapType.ProtocolIEIDUEPagingIdentity {
			amfSetId := "fe"
			tmsiRaw := ie.Value.UEPagingIdentity.FiveGSTMSI.FiveGTMSI.Value
			tmsi := 0
			for idx, val := range tmsiRaw {
				tmsi += int(val)
				if idx != len(tmsiRaw)-1 {
					tmsi <<= 1
				}

			}
			// TODO: modify this
			sTmsi = fmt.Sprintf("%s%010x", amfSetId, tmsi)
		}
	}

	return
}

func GetIpAddressFromPDUSessionResourceSetupRequest(
	ue *RanUeContext, msg *ngapType.PDUSessionResourceSetupRequest,
) (address string, err error) {
	for _, ie := range msg.ProtocolIEs.List {
		if ie.Id.Value == ngapType.ProtocolIEIDPDUSessionResourceSetupListSUReq {
			for _, pduSetupItem := range ie.Value.PDUSessionResourceSetupListSUReq.List {
				pkg := []byte(pduSetupItem.PDUSessionNASPDU.Value)
				// fmt.Printf("byte: %v\n", pkg)
				m, err := NASDecode(ue, nas.GetSecurityHeaderType(pkg), pkg)
				if err != nil {
					return "", err
				}
				pkg = m.GmmMessage.DLNASTransport.PayloadContainer.GetPayloadContainerContents()
				err = m.PlainNasDecode(&pkg)
				if err != nil {
					return "", err
				}
				addressInformation := m.GsmMessage.PDUAddress.GetPDUAddressInformation()
				address = ""
				for idx, val := range addressInformation {
					if idx == 4 { // IPv4
						break
					}
					address += strconv.FormatInt(int64(val), 10)
					if idx != 3 {
						address += "."
					}
				}
			}
		}
	}

	return
}
