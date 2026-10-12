package quickfox

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kfadapter/kfadapter/internal/provider"
)

func TestDriverLoginAndRefreshEncryptedControlProtocol(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 22, 6, 0, 0, 0, time.UTC)
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls++
		if request.Header.Get("version") != clientVersion || request.Header.Get("platformType") != platformType || request.Header.Get("channel") != "official" || request.Header.Get("lang") != "zh_CN" {
			t.Errorf("request headers = %#v", request.Header)
		}
		if request.Header.Get("deviceCode") != "00112233-4455-4677-8899-aabbccddeeff" || len(request.Header.Get("nonce")) != 32 {
			t.Errorf("request identity headers = %#v", request.Header)
		}
		payload := map[string]any{}
		if request.Method != http.MethodGet {
			payload = decryptRequestPayload(t, request.Body)
		}
		switch request.URL.Path {
		case "/user/login":
			if request.Header.Get("token") != "" || payload["email"] != "alice@example.com" || payload["password"] != "5f4dcc3b5aa765d61d8327deb882cf99" || payload["platform"] != "pc" {
				t.Errorf("login request = %#v", payload)
			}
			writeEncryptedResponse(t, writer, map[string]any{
				"token": "0123456789abcdef0123456789abcdef", "userId": 15904241,
				"email": "alice@example.com", "username": "alice", "vipTime": "98",
				"vipInfo": []any{map[string]any{"endTime": "2026-08-22 14:00:00", "grade": 1}},
			})
		case "/user/info":
			if request.Method != http.MethodGet || request.Header.Get("token") != "0123456789abcdef0123456789abcdef" {
				t.Errorf("profile request = method %s headers %#v", request.Method, request.Header)
			}
			writeEncryptedResponse(t, writer, map[string]any{
				"userId": 15904241, "email": "alice@example.com", "username": "alice", "vipTime": "98",
				"vipInfo": []any{map[string]any{"endTime": "2026-08-22 14:00:00", "grade": 1}},
			})
		case "/line/socksServerPoolList":
			if request.Header.Get("token") != "0123456789abcdef0123456789abcdef" || payload["lineTypeId"] != float64(2) || payload["type"] != float64(1) {
				t.Errorf("catalog request = headers %#v payload %#v", request.Header, payload)
			}
			fixture := catalogFixture()
			fixture.Profile.VIPSubscription = nil
			writeEncryptedResponse(t, writer, fixture)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Location: time.FixedZone("Asia/Shanghai", 8*60*60), Clock: func() time.Time { return now },
		Random: bytes.NewReader(bytes.Repeat([]byte{0x5a}, 96)), RequestTimeout: time.Second,
		httpClient: server.Client(), apiBase: server.URL,
	})
	if err != nil {
		t.Fatal(err)
	}
	driver, err := NewDriver(DriverConfig{Client: client, Clock: func() time.Time { return now }, AuthorityLifetime: 12 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := driver.Login(context.Background(), provider.Credentials{Account: " alice@example.com ", Password: "password", InstallationID: "00112233445566778899aabbccddeeff"})
	if err != nil {
		t.Fatal(err)
	}
	assertSnapshot(t, snapshot, now)
	refreshed, err := driver.Refresh(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	assertSnapshot(t, refreshed, now)
	if calls != 5 {
		t.Fatalf("control calls = %d, want 5", calls)
	}
}

func TestDriverRejectsMalformedCatalogLine(t *testing.T) {
	t.Parallel()
	fixture := catalogFixture()
	fixture.Groups[0].Regions[0].Lines[0].ConnectIP = "example.com"
	if _, err := nodesFromCatalog(fixture.Groups, vipTier); !errors.Is(err, ErrInvalidLine) {
		t.Fatalf("nodesFromCatalog error = %v, want ErrInvalidLine", err)
	}
}

func TestQuickFoxTiersControlFeeEligibility(t *testing.T) {
	t.Parallel()
	fixture := catalogFixture()
	feeTwo := fixture.Groups[0].Regions[0].Lines[1]
	feeTwo.PoolID = 1218
	feeTwo.ConnectPort++
	feeTwo.Name = "VIP备用专线"
	feeTwo.PoolName = feeTwo.Name
	feeTwo.FeeType = 2
	feeThree := fixture.Groups[0].Regions[0].Lines[1]
	feeThree.PoolID = 1219
	feeThree.ConnectPort += 2
	feeThree.Name = "SVIP专线"
	feeThree.PoolName = feeThree.Name
	feeThree.FeeType = 3
	fixture.Groups[0].Regions[0].Lines = append(fixture.Groups[0].Regions[0].Lines, feeTwo, feeThree)
	for _, test := range []struct {
		tier string
		want string
	}{
		{tier: standardTier, want: "洛杉矶自F区"},
		{tier: vipTier, want: "洛杉矶自F区,西雅图专线,VIP备用专线"},
		{tier: svipTier, want: "洛杉矶自F区,西雅图专线,VIP备用专线,SVIP专线"},
	} {
		nodes, err := nodesFromCatalog(fixture.Groups, test.tier)
		if err != nil {
			t.Fatal(err)
		}
		names := make([]string, len(nodes))
		for index := range nodes {
			if !nodes[index].Eligible {
				t.Fatalf("%s node is ineligible: %#v", test.tier, nodes[index])
			}
			names[index] = nodes[index].Name
		}
		if got := strings.Join(names, ","); got != test.want {
			t.Fatalf("%s nodes = %q, want %q", test.tier, got, test.want)
		}
	}
}

func TestPositiveVIPTimeGrantsVIPAccess(t *testing.T) {
	now := time.Date(2026, 7, 22, 6, 0, 0, 0, time.UTC)
	payload := accountPayload{
		UserID: 15904241, Email: "alice@example.com", VIPTime: 98,
		VIPSubscription: []vipPeriod{
			{EndTime: "2026-08-22 14:00:00", Grade: 1},
			{EndTime: "2026-09-22 14:00:00", Grade: 2},
		},
	}
	account, err := payload.account(time.FixedZone("Asia/Shanghai", 8*60*60), now)
	if err != nil {
		t.Fatal(err)
	}
	if account.Tier != vipTier || !account.SubscriptionActive || !account.SubscriptionEndsAt.Equal(time.Date(2026, 8, 22, 6, 0, 0, 0, time.UTC)) {
		t.Fatalf("VIP account = %#v", account)
	}
}

func TestPositiveSVIPTimeGrantsSVIPAccess(t *testing.T) {
	now := time.Date(2026, 7, 22, 6, 0, 0, 0, time.UTC)
	payload := accountPayload{
		UserID: 15904241, Email: "alice@example.com", VIPTime: 98, SVIP: svipStatus{Time: 30},
		VIPSubscription: []vipPeriod{
			{EndTime: "2026-08-22 14:00:00", Grade: 1},
			{EndTime: "2026-09-22 14:00:00", Grade: 2},
		},
	}
	account, err := payload.account(time.FixedZone("Asia/Shanghai", 8*60*60), now)
	if err != nil {
		t.Fatal(err)
	}
	if account.Tier != svipTier || !account.SubscriptionActive || !account.SubscriptionEndsAt.Equal(time.Date(2026, 9, 22, 6, 0, 0, 0, time.UTC)) {
		t.Fatalf("SVIP account = %#v", account)
	}
}

func TestPayFlagsAndVIPPeriodsDoNotReplaceOriginalVIPCountdown(t *testing.T) {
	now := time.Date(2026, 7, 22, 6, 0, 0, 0, time.UTC)
	encoded := []byte(`{"userId":15904241,"email":"alice@example.com","vipTime":"0","payVipFlag":true,"userPayVipFlag":1,"exclusiveFlag":true,"userPayExclusiveFlag":1,"svip":{"svipDay":-214,"svipTime":-214},"vipInfo":[{"endTime":"2026-08-22 14:00:00","grade":2}]}`)
	var payload accountPayload
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatal(err)
	}
	account, err := payload.account(time.FixedZone("Asia/Shanghai", 8*60*60), now)
	if err != nil {
		t.Fatal(err)
	}
	if account.Tier != standardTier || account.SubscriptionActive || !account.SubscriptionEndsAt.IsZero() {
		t.Fatalf("standard account = %#v", account)
	}
}

func TestAccountRequiresQuotedVIPTime(t *testing.T) {
	t.Parallel()
	for _, encoded := range []string{
		`{"userId":15904241,"email":"alice@example.com","vipTime":98}`,
		`{"userId":15904241,"email":"alice@example.com","vipTime":"not-a-number"}`,
	} {
		var payload accountPayload
		if err := json.Unmarshal([]byte(encoded), &payload); err == nil {
			t.Fatalf("malformed vipTime accepted: %s", encoded)
		}
	}
}

func TestPaidProfileRequiresMatchingFutureExactExpiry(t *testing.T) {
	now := time.Date(2026, 7, 22, 6, 0, 0, 0, time.UTC)
	profiles := []accountPayload{
		{UserID: 15904241, Email: "alice@example.com", VIPTime: 98},
		{UserID: 15904241, Email: "alice@example.com", SVIP: svipStatus{Time: 1}},
		{UserID: 15904241, Email: "alice@example.com", VIPTime: 98, VIPSubscription: []vipPeriod{{EndTime: "2026-07-21 14:00:00", Grade: 1}}},
		{UserID: 15904241, Email: "alice@example.com", VIPTime: 98, VIPSubscription: []vipPeriod{{EndTime: "2026-08-22 14:00:00", Grade: 2}}},
		{UserID: 15904241, Email: "alice@example.com", SVIP: svipStatus{Time: 1}, VIPSubscription: []vipPeriod{{EndTime: "2026-08-22 14:00:00", Grade: 1}}},
	}
	for _, profile := range profiles {
		if _, err := profile.account(time.FixedZone("Asia/Shanghai", 8*60*60), now); !errors.Is(err, ErrSchema) {
			t.Fatalf("paid profile without matching future expiry error = %v", err)
		}
	}
}

func assertSnapshot(t *testing.T, snapshot provider.Snapshot, now time.Time) {
	t.Helper()
	if snapshot.Provider != ProviderID || snapshot.Account.UserID != "15904241" || snapshot.Account.Display != "a•••@example.com" || snapshot.Account.Tier != vipTier || !snapshot.Account.SubscriptionActive {
		t.Fatalf("account snapshot = %#v", snapshot)
	}
	if !snapshot.ExpiresAt.Equal(now.Add(12*time.Hour)) || len(snapshot.Authorities) != 1 || len(snapshot.Nodes) != 2 {
		t.Fatalf("snapshot shape = %#v", snapshot)
	}
	if snapshot.Nodes[0].ID == snapshot.Nodes[1].ID || snapshot.Nodes[0].Group != "国内模式 / 美国节点" || snapshot.Nodes[0].Model != "国内模式" || !snapshot.Nodes[0].Eligible || !snapshot.Nodes[1].Eligible {
		t.Fatalf("snapshot nodes = %#v", snapshot.Nodes)
	}
	stored, err := decodeStoredSession(snapshot.RefreshState)
	if err != nil || stored.Token != "0123456789abcdef0123456789abcdef" || stored.DeviceCode != "00112233-4455-4677-8899-aabbccddeeff" {
		t.Fatalf("stored session = %#v, %v", stored, err)
	}
	if strings.Contains(string(snapshot.RefreshState), "password") {
		t.Fatal("refresh state retained password")
	}
}

func decryptRequestPayload(t *testing.T, body io.Reader) map[string]any {
	t.Helper()
	var envelope struct {
		Data string `json:"data"`
	}
	if err := json.NewDecoder(body).Decode(&envelope); err != nil {
		t.Fatal(err)
	}
	ciphertext, err := base64.StdEncoding.DecodeString(envelope.Data)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := decryptCBC(ciphertext, []byte(requestKey))
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		t.Fatal(err)
	}
	return payload
}

func writeEncryptedResponse(t *testing.T, writer http.ResponseWriter, data any) {
	t.Helper()
	plaintext, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := encryptCBC(plaintext, []byte(responseKey))
	if err != nil {
		t.Fatal(err)
	}
	code, success := http.StatusOK, true
	if err := json.NewEncoder(writer).Encode(envelope{Code: &code, Data: json.RawMessage(strconvQuote(base64.StdEncoding.EncodeToString(ciphertext))), Success: &success}); err != nil {
		t.Fatal(err)
	}
}

func strconvQuote(value string) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}

func catalogFixture() catalog {
	status := 1
	regionID := 30
	return catalog{
		Profile: accountPayload{
			UserID: 15904241, Email: "alice@example.com", Username: "alice", VIPTime: 98,
			VIPSubscription: []vipPeriod{{EndTime: "2026-08-22 14:00:00", Grade: 1}},
		},
		Groups: []lineGroup{{
			TypeID: 2, TypeName: "国内模式", Regions: []lineRegion{{RegionID: &regionID, Name: "美国节点", Lines: []linePool{
				{PoolID: 1191, Name: "洛杉矶自F区", PoolName: "洛杉矶自F区", ConnectIP: "117.24.248.147", ConnectPort: 443, ProtocolType: "socks", FeeType: 0, Status: &status},
				{PoolID: 1217, Name: "西雅图专线", PoolName: "西雅图专线", ConnectIP: "34.160.111.145", ConnectPort: 80, ProtocolType: "socks", FeeType: 1, Status: &status},
			}}},
		}},
	}
}
