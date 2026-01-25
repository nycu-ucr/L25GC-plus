package test

import (
	"encoding/json"
	"fmt"

	"github.com/calee0219/fatal"
	"go.mongodb.org/mongo-driver/bson"

	"github.com/free5gc/MongoDBLibrary"
	"github.com/nycu-ucr/openapi/models"
)

func toBsonM(data interface{}) bson.M {
	tmp, err := json.Marshal(data)
	if err != nil {
		fatal.Fatalf("Marshal error in toBsonM: %+v", err)
	}
	var putData = bson.M{}
	err = json.Unmarshal(tmp, &putData)
	if err != nil {
		fatal.Fatalf("Unmarshal error in toBsonM: %+v", err)
	}
	return putData
}

// func InsertUeToMongoDB(t *testing.T, ue *RanUeContext, servingPlmnId string) {
// 	InsertAuthSubscriptionToMongoDB(ue.Supi, ue.AuthenticationSubs)
// 	InsertWebAuthSubscriptionToMongoDB(ue.Supi, ue.AuthenticationSubs)
// 	getData := GetAuthSubscriptionFromMongoDB(ue.Supi)
// 	assert.NotNil(t, getData)
// 	{
// 		amData := GetAccessAndMobilitySubscriptionData()
// 		InsertAccessAndMobilitySubscriptionDataToMongoDB(ue.Supi, amData, servingPlmnId)
// 		getData := GetAccessAndMobilitySubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)
// 		assert.NotNil(t, getData)
// 	}
// 	{
// 		smfSelData := GetSmfSelectionSubscriptionData()
// 		InsertSmfSelectionSubscriptionDataToMongoDB(ue.Supi, smfSelData, servingPlmnId)
// 		getData := GetSmfSelectionSubscriptionDataFromMongoDB(ue.Supi, servingPlmnId)
// 		assert.NotNil(t, getData)
// 	}
// 	{
// 		smSelData := GetSessionManagementSubscriptionData()
// 		InsertSessionManagementSubscriptionDataToMongoDB(ue.Supi, servingPlmnId, smSelData)
// 		getData := GetSessionManagementDataFromMongoDB(ue.Supi, servingPlmnId)
// 		assert.NotNil(t, getData)
// 	}
// 	{
// 		amPolicyData := GetAmPolicyData()
// 		InsertAmPolicyDataToMongoDB(ue.Supi, amPolicyData)
// 		getData := GetAmPolicyDataFromMongoDB(ue.Supi)
// 		assert.NotNil(t, getData)
// 	}
// 	{
// 		smPolicyData := GetSmPolicyData()
// 		InsertSmPolicyDataToMongoDB(ue.Supi, smPolicyData)
// 		getData := GetSmPolicyDataFromMongoDB(ue.Supi)
// 		assert.NotNil(t, getData)
// 	}
// 	{
// 		chargingDatas := GetChargingData()
// 		InsertChargingDataToMongoDB(ue.Supi, servingPlmnId, chargingDatas)
// 		getData := GetSmPolicyDataFromMongoDB(ue.Supi)
// 		assert.NotNil(t, getData)
// 	}
// 	{
// 		flowRules := GetFlowRuleData()
// 		InsertFlowRuleToMongoDB(ue.Supi, servingPlmnId, flowRules)
// 		getData := GetSmPolicyDataFromMongoDB(ue.Supi)
// 		assert.NotNil(t, getData)
// 	}
// 	{
// 		qosFlows := GetQosFlowData()
// 		InsertQoSFlowToMongoDB(ue.Supi, servingPlmnId, qosFlows)
// 		getData := GetSmPolicyDataFromMongoDB(ue.Supi)
// 		assert.NotNil(t, getData)
// 	}
// }

func InsertAuthSubscriptionToMongoDB(ueId string, authSubs models.AuthenticationSubscription) {
	collName := "subscriptionData.authenticationData.authenticationSubscription"
	filter := bson.M{"ueId": ueId}
	putData := toBsonM(authSubs)
	putData["ueId"] = ueId

	// Convert from old model structure (test code) to new model structure (UDM expects)
	// Old: SequenceNumber is a string, PermanentKey is struct, Opc is struct
	// New: SequenceNumber is struct with sqn field, EncPermanentKey is string, EncOpcKey is string

	// Convert sequenceNumber from string to struct for UDM compatibility
	if seqNumStr, ok := putData["sequenceNumber"].(string); ok {
		putData["sequenceNumber"] = bson.M{
			"sqn": seqNumStr,
		}
	}

	// Convert PermanentKey struct to EncPermanentKey string for UDM compatibility
	if permKey, ok := putData["permanentKey"]; ok && permKey != nil {
		var permKeyObj map[string]interface{}
		switch v := permKey.(type) {
		case bson.M:
			permKeyObj = map[string]interface{}(v)
		case map[string]interface{}:
			permKeyObj = v
		default:
			if m, ok := v.(map[string]interface{}); ok {
				permKeyObj = m
			}
		}
		if permKeyObj != nil {
			if permKeyValue, ok := permKeyObj["permanentKeyValue"].(string); ok {
				putData["encPermanentKey"] = permKeyValue
				delete(putData, "permanentKey") // Remove old field
			}
		}
	}

	// Convert Opc struct to EncOpcKey string for UDM compatibility
	if opc, ok := putData["opc"]; ok && opc != nil {
		var opcObj map[string]interface{}
		switch v := opc.(type) {
		case bson.M:
			opcObj = map[string]interface{}(v)
		case map[string]interface{}:
			opcObj = v
		default:
			if m, ok := v.(map[string]interface{}); ok {
				opcObj = m
			}
		}
		if opcObj != nil {
			if opcValue, ok := opcObj["opcValue"].(string); ok {
				putData["encOpcKey"] = opcValue
				delete(putData, "opc") // Remove old field
			}
		}
	}

	MongoDBLibrary.RestfulAPIPutOne(collName, filter, putData)
}

func GetAuthSubscriptionFromMongoDB(ueId string) (authSubs *models.AuthenticationSubscription) {
	collName := "subscriptionData.authenticationData.authenticationSubscription"
	filter := bson.M{"ueId": ueId}
	getData := MongoDBLibrary.RestfulAPIGetOne(collName, filter)
	if getData == nil {
		return
	}

	// Convert from new model structure (UDM stores) to old model structure (test code expects)
	// New: SequenceNumber is struct with sqn field, EncPermanentKey is string, EncOpcKey is string
	// Old: SequenceNumber is a string, PermanentKey is struct, Opc is struct

	// Convert sequenceNumber from struct to string for test code compatibility
	if seqNumRaw, ok := getData["sequenceNumber"]; ok && seqNumRaw != nil {
		// Check if it's already a string (old format)
		if _, ok := seqNumRaw.(string); !ok {
			// Try to extract sqn from object structure (new format from UDM)
			var obj map[string]interface{}
			switch v := seqNumRaw.(type) {
			case bson.M:
				obj = map[string]interface{}(v)
			case map[string]interface{}:
				obj = v
			default:
				if m, ok := v.(map[string]interface{}); ok {
					obj = m
				}
			}
			if obj != nil {
				if sqn, ok := obj["sqn"].(string); ok {
					getData["sequenceNumber"] = sqn
				} else if sqnVal, ok := obj["sqn"]; ok {
					// If sqn is not a string, convert it
					getData["sequenceNumber"] = fmt.Sprintf("%v", sqnVal)
				}
			}
		}
	}

	// Convert EncPermanentKey string to PermanentKey struct for test code compatibility
	if encPermanentKey, ok := getData["encPermanentKey"].(string); ok {
		getData["permanentKey"] = bson.M{
			"permanentKeyValue": encPermanentKey,
		}
		delete(getData, "encPermanentKey") // Remove old field
	}

	// Convert EncOpcKey string to Opc struct for test code compatibility
	if encOpcKey, ok := getData["encOpcKey"].(string); ok {
		getData["opc"] = bson.M{
			"opcValue": encOpcKey,
		}
		delete(getData, "encOpcKey") // Remove old field
	}

	tmp, err := json.Marshal(getData)
	if err != nil {
		return
	}
	authSubs = new(models.AuthenticationSubscription)
	err = json.Unmarshal(tmp, authSubs)
	if err != nil {
		fatal.Fatalf("Unmarshal error in GetAuthSubscriptionFromMongoDB: %+v", err)
	}
	return
}

func DelAuthSubscriptionToMongoDB(ueId string) {
	collName := "subscriptionData.authenticationData.authenticationSubscription"
	filter := bson.M{"ueId": ueId}
	MongoDBLibrary.RestfulAPIDeleteMany(collName, filter)
}

func InsertAccessAndMobilitySubscriptionDataToMongoDB(
	ueId string, amData models.AccessAndMobilitySubscriptionData, servingPlmnId string) {
	collName := "subscriptionData.provisionedData.amData"
	filter := bson.M{"ueId": ueId, "servingPlmnId": servingPlmnId}
	putData := toBsonM(amData)
	putData["ueId"] = ueId
	putData["servingPlmnId"] = servingPlmnId
	MongoDBLibrary.RestfulAPIPutOne(collName, filter, putData)
}

func GetAccessAndMobilitySubscriptionDataFromMongoDB(
	ueId string, servingPlmnId string) (amData *models.AccessAndMobilitySubscriptionData) {
	collName := "subscriptionData.provisionedData.amData"
	filter := bson.M{"ueId": ueId, "servingPlmnId": servingPlmnId}
	getData := MongoDBLibrary.RestfulAPIGetOne(collName, filter)
	if getData == nil {
		return
	}
	tmp, err := json.Marshal(getData)
	if err != nil {
		return
	}
	amData = new(models.AccessAndMobilitySubscriptionData)
	err = json.Unmarshal(tmp, amData)
	if err != nil {
		fatal.Fatalf("Unmarshal error in GetAccessAndMobilitySubscriptionDataFromMongoDB: %+v", err)
	}
	return
}

func DelAccessAndMobilitySubscriptionDataFromMongoDB(ueId string, servingPlmnId string) {
	collName := "subscriptionData.provisionedData.amData"
	filter := bson.M{"ueId": ueId, "servingPlmnId": servingPlmnId}
	MongoDBLibrary.RestfulAPIDeleteMany(collName, filter)
}

func InsertSessionManagementSubscriptionDataToMongoDB(
	ueId string, servingPlmnId string, smDatas []models.SessionManagementSubscriptionData) {
	var putDatas = make([]interface{}, 0, len(smDatas))
	collName := "subscriptionData.provisionedData.smData"
	filter := bson.M{"ueId": ueId, "servingPlmnId": servingPlmnId}
	for _, smData := range smDatas {
		putData := toBsonM(smData)
		putData["ueId"] = ueId
		putData["servingPlmnId"] = servingPlmnId
		putDatas = append(putDatas, putData)
	}
	MongoDBLibrary.RestfulAPIPostMany(collName, filter, putDatas)
}

func GetSessionManagementDataFromMongoDB(
	ueId string, servingPlmnId string) (amData *models.SessionManagementSubscriptionData) {
	collName := "subscriptionData.provisionedData.smData"
	filter := bson.M{"ueId": ueId, "servingPlmnId": servingPlmnId}
	getData := MongoDBLibrary.RestfulAPIGetOne(collName, filter)
	if getData == nil {
		return
	}
	tmp, err := json.Marshal(getData)
	if err != nil {
		return
	}
	amData = new(models.SessionManagementSubscriptionData)
	err = json.Unmarshal(tmp, amData)
	if err != nil {
		fatal.Fatalf("Unmarshal error in GetSessionManagementDataFromMongoDB: %+v", err)
	}
	return
}

func DelSessionManagementSubscriptionDataFromMongoDB(ueId string, servingPlmnId string) {
	collName := "subscriptionData.provisionedData.smData"
	filter := bson.M{"ueId": ueId, "servingPlmnId": servingPlmnId}
	MongoDBLibrary.RestfulAPIDeleteMany(collName, filter)
}

func InsertSmfSelectionSubscriptionDataToMongoDB(
	ueId string, smfSelData models.SmfSelectionSubscriptionData, servingPlmnId string) {
	collName := "subscriptionData.provisionedData.smfSelectionSubscriptionData"
	filter := bson.M{"ueId": ueId, "servingPlmnId": servingPlmnId}
	putData := toBsonM(smfSelData)
	putData["ueId"] = ueId
	putData["servingPlmnId"] = servingPlmnId
	MongoDBLibrary.RestfulAPIPutOne(collName, filter, putData)
}

func GetSmfSelectionSubscriptionDataFromMongoDB(
	ueId string, servingPlmnId string) (smfSelData *models.SmfSelectionSubscriptionData) {
	collName := "subscriptionData.provisionedData.smfSelectionSubscriptionData"
	filter := bson.M{"ueId": ueId, "servingPlmnId": servingPlmnId}
	getData := MongoDBLibrary.RestfulAPIGetOne(collName, filter)
	if getData == nil {
		return
	}
	tmp, err := json.Marshal(getData)
	if err != nil {
		return
	}
	smfSelData = new(models.SmfSelectionSubscriptionData)
	err = json.Unmarshal(tmp, smfSelData)
	if err != nil {
		fatal.Fatalf("Unmarshal error in GetSmfSelectionSubscriptionDataFromMongoDB: %+v", err)
	}
	return
}

func DelSmfSelectionSubscriptionDataFromMongoDB(ueId string, servingPlmnId string) {
	collName := "subscriptionData.provisionedData.smfSelectionSubscriptionData"
	filter := bson.M{"ueId": ueId, "servingPlmnId": servingPlmnId}
	MongoDBLibrary.RestfulAPIDeleteMany(collName, filter)
}

func InsertAmPolicyDataToMongoDB(ueId string, amPolicyData models.AmPolicyData) {
	collName := "policyData.ues.amData"
	filter := bson.M{"ueId": ueId}
	putData := toBsonM(amPolicyData)
	putData["ueId"] = ueId
	MongoDBLibrary.RestfulAPIPutOne(collName, filter, putData)
}

func GetAmPolicyDataFromMongoDB(ueId string) (amPolicyData *models.AmPolicyData) {
	collName := "policyData.ues.amData"
	filter := bson.M{"ueId": ueId}
	getData := MongoDBLibrary.RestfulAPIGetOne(collName, filter)
	if getData == nil {
		return
	}
	tmp, err := json.Marshal(getData)
	if err != nil {
		return
	}
	amPolicyData = new(models.AmPolicyData)
	err = json.Unmarshal(tmp, amPolicyData)
	if err != nil {
		fatal.Fatalf("Unmarshal error in GetAmPolicyDataFromMongoDB: %+v", err)
	}
	return
}

func DelAmPolicyDataFromMongoDB(ueId string) {
	collName := "policyData.ues.amData"
	filter := bson.M{"ueId": ueId}
	MongoDBLibrary.RestfulAPIDeleteMany(collName, filter)
}

func InsertSmPolicyDataToMongoDB(ueId string, smPolicyData models.SmPolicyData) {
	collName := "policyData.ues.smData"
	filter := bson.M{"ueId": ueId}
	putData := toBsonM(smPolicyData)
	putData["ueId"] = ueId
	MongoDBLibrary.RestfulAPIPutOne(collName, filter, putData)
}

func GetSmPolicyDataFromMongoDB(ueId string) (smPolicyData *models.SmPolicyData) {
	collName := "policyData.ues.smData"
	filter := bson.M{"ueId": ueId}
	getData := MongoDBLibrary.RestfulAPIGetOne(collName, filter)
	if getData == nil {
		return
	}
	tmp, err := json.Marshal(getData)
	if err != nil {
		return
	}
	smPolicyData = new(models.SmPolicyData)
	err = json.Unmarshal(tmp, smPolicyData)
	if err != nil {
		fatal.Fatalf("Unmarshal error in GetSmPolicyDataFromMongoDB: %+v", err)
	}
	return
}

func DelSmPolicyDataFromMongoDB(ueId string) {
	collName := "policyData.ues.smData"
	filter := bson.M{"ueId": ueId}
	MongoDBLibrary.RestfulAPIDeleteMany(collName, filter)
}
