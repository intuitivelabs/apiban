package apiban

import (
	//"fmt"
	//"github.com/google/nftables"
	//"strconv"
	"testing"
	//"time"
)

func TestApi(t *testing.T) {
	var (
		response Response
		err      error
	)
	/*
		jsonUri := []byte(
			`{
				"metadata": {
				"Generatedat": 1631709422,
				"Generatedby": "IntuitiveLabs",
				"Count": 1,
				"ScannedCount": 1,
				"ApiParameters": {
				  "list": "uriblack",
				  "token": "NeBvq0stHyADinphZSMk0qnWdh2rE6xg9GU1pjP3SotlKmSpEKNDuXmOKFX2fWQ9",
				  "timestamp": 0
				},
				"dynamoParams": {
				  "ExpressionAttributeValues": {
					":start_ts": 0,
					":div": "294ddd10-75e3-4443-8c91-683abb4a3f20#uriblack"
				  },
				  "ExpressionAttributeNames": {
					"#ts": "timestamp",
					"#did": "domain"
				  },
				  "KeyConditionExpression": "#did = :div AND #ts > :start_ts",
				  "TableName": "vbpridata-IPBlacklist-X71WLHMK0JIQ",
				  "IndexName": "vbpridata-ipblacklistgsi"
				},
				"endnote": "no more items",
				"firstKey": {
				  "IP": "294ddd10-75e3-4443-8c91-683abb4a3f20#sip:QT982R6B7O3HAINUE93L6I8QCQC3C1LM77P9RTSNDAE4KIKE5SE0----@LH6A2Q4E68903SC1R514CN8FDO------",
				  "domain": "294ddd10-75e3-4443-8c91-683abb4a3f20#uriblack",
				  "timestamp": 1631007221
				},
				"firstEncodedKey": "eyJJUCI6IjI5NGRkZDEwLTc1ZTMtNDQ0My04YzkxLTY4M2FiYjRhM2YyMCNzaXA6UVQ5ODJSNkI3TzNIQUlOVUU5M0w2SThRQ1FDM0MxTE03N1A5UlRTTkRBRTRLSUtFNVNFMC0tLS1ATEg2QTJRNEU2ODkwM1NDMVI1MTRDTjhGRE8tLS0tLS0iLCJkb21haW4iOiIyOTRkZGQxMC03NWUzLTQ0NDMtOGM5MS02ODNhYmI0YTNmMjAjdXJpYmxhY2siLCJ0aW1lc3RhbXAiOjE2MzEwMDcyMjF9",
				"defaultBlacklistTtl": 172800,
				"lastTimestamp": 1631007221
			  },
			  "elements": [
				{
				  "encrypt": "294ddd10-75e3-4443-8c91-683abb4a3f20",
				  "exceeded": "API",
				  "count": 1,
				  "evntcnt": 1,
				  "timestamp": 1631007221,
				  "IP": "294ddd10-75e3-4443-8c91-683abb4a3f20#sip:QT982R6B7O3HAINUE93L6I8QCQC3C1LM77P9RTSNDAE4KIKE5SE0----@LH6A2Q4E68903SC1R514CN8FDO------",
				  "uri": "sip:QT982R6B7O3HAINUE93L6I8QCQC3C1LM77P9RTSNDAE4KIKE5SE0----@LH6A2Q4E68903SC1R514CN8FDO------",
				  "domain": "294ddd10-75e3-4443-8c91-683abb4a3f20#uriblack"
				}
			  ]
			}`)
	*/
	jsonIp := []byte(
		`{
	"metadata": {
	"Generatedat": 1631714171,
	"Generatedby": "IntuitiveLabs",
	"Count": 1,
	"ScannedCount": 1,
	"ApiParameters": {
	  "list": "ipblack",
	  "token": "NeBvq0stHyADinphZSMk0qnWdh2rE6xg9GU1pjP3SotlKmSpEKNDuXmOKFX2fWQ9",
	  "timestamp": 0
	},
	"dynamoParams": {
	  "ExpressionAttributeValues": {
		":start_ts": 0,
		":div": "294ddd10-75e3-4443-8c91-683abb4a3f20#ipblack"
	  },
	  "ExpressionAttributeNames": {
		"#ts": "timestamp",
		"#did": "domain"
	  },
	  "KeyConditionExpression": "#did = :div AND #ts > :start_ts",
	  "TableName": "vbpridata-IPBlacklist-X71WLHMK0JIQ",
	  "IndexName": "vbpridata-ipblacklistgsi"
	},
	"endnote": "no more items",
	"firstKey": {
	  "IP": "294ddd10-75e3-4443-8c91-683abb4a3f20#51.100.57.107",
	  "domain": "294ddd10-75e3-4443-8c91-683abb4a3f20#ipblack",
	  "timestamp": 1631005178
	},
	"firstEncodedKey": "eyJJUCI6IjI5NGRkZDEwLTc1ZTMtNDQ0My04YzkxLTY4M2FiYjRhM2YyMCM1MS4xMDAuNTcuMTA3IiwiZG9tYWluIjoiMjk0ZGRkMTAtNzVlMy00NDQzLThjOTEtNjgzYWJiNGEzZjIwI2lwYmxhY2siLCJ0aW1lc3RhbXAiOjE2MzEwMDUxNzh9",
	"defaultBlacklistTtl": 172800,
	"lastTimestamp": 1631005178
  },
  "elements": [
	{
	  "encrypt": "2c1db:294ddd10-75e3-4443-8c91-683abb4a3f20",
	  "exceeded": "API",
	  "count": 1,
	  "ipaddr": "51.100.57.107",
	  "evntcnt": 1,
	  "timestamp": 1631005178,
	  "IP": "294ddd10-75e3-4443-8c91-683abb4a3f20#51.100.57.107",
	  "domain": "294ddd10-75e3-4443-8c91-683abb4a3f20#ipblack"
	}
  ]
}`)
	config = Config{
		Passphrase:  "reallyworks?",
		Table:       "filter",
		FwdChain:    "FORWARD",
		InChain:     "INPUT",
		TgtChain:    "MONITORING",
		DryRun:      true,
		UseNftables: true,
	}
	InitEncryption(&config)
	RegisterIpApis("", "", "")
	if _, err := InitializeFirewall("blacklist", "whitelist", config.DryRun); err != nil {
		t.Fatalf("failed to initialize firewall: %s", err)
	}
	t.Run("ipblack parse", func(t *testing.T) {
		response, err = Apis[IpBanned].parseResponse(jsonIp)
		if err != nil {
			t.Fatalf("parse response %s error: %s ", string(jsonIp), err)
		}
		if response.(*JSONResponse) == nil {
			t.Fatalf("invalid response type")
		}
	})
	t.Run("ipblack process", func(t *testing.T) {
		cnt, err := response.(*JSONResponse).processElements(1, Apis[IpBanned])
		if err != nil {
			t.Fatalf("failed to process response \n%s\nerror: %s", string(jsonIp), err)
		}
		if cnt != 1 {
			t.Fatalf("failed to process response elements")
		}
	})
	t.Run("ipwhite parse", func(t *testing.T) {
		response, err = Apis[IpAllowed].parseResponse(jsonIp)
		if err != nil {
			t.Fatalf("parse response %s error: %s ", string(jsonIp), err)
		}
		if response.(*JSONResponse) == nil {
			t.Fatalf("invalid response type")
		}
	})
	t.Run("ipwhite process", func(t *testing.T) {
		cnt, err := response.(*JSONResponse).processElements(1, Apis[IpAllowed])
		if err != nil {
			t.Fatalf("failed to process response \n%s\nerror: %s", string(jsonIp), err)
		}
		if cnt != 1 {
			t.Fatalf("failed to process response elements")
		}
	})
}
