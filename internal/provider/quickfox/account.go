package quickfox

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/oshinop/chinadapter/internal/provider"
)

type vipPeriod struct {
	EndTime string `json:"endTime"`
	Grade   int    `json:"grade"`
}

type svipStatus struct {
	Time int64 `json:"svipTime"`
}

type accountPayload struct {
	Token           string      `json:"token"`
	UserID          int64       `json:"userId"`
	Email           string      `json:"email"`
	Username        string      `json:"username"`
	VIPTime         flexInt64   `json:"vipTime"`
	SVIP            svipStatus  `json:"svip"`
	VIPSubscription []vipPeriod `json:"vipInfo"`
}

// flexInt64 accepts an integer sent either as a JSON number or as a quoted
// decimal string; QuickFox has used both forms for vipTime. Anything else,
// including fractions and non-numeric strings, is rejected.
type flexInt64 int64

func (value *flexInt64) UnmarshalJSON(data []byte) error {
	text := string(data)
	if text == "null" {
		return nil
	}
	if len(text) >= 2 && text[0] == '"' && text[len(text)-1] == '"' {
		text = text[1 : len(text)-1]
	}
	parsed, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return fmt.Errorf("%w: integer field", ErrSchema)
	}
	*value = flexInt64(parsed)
	return nil
}

type loginResponse struct {
	accountPayload
}

func (payload accountPayload) account(location *time.Location, now time.Time) (provider.Account, error) {
	if payload.UserID <= 0 {
		return provider.Account{}, ErrSchema
	}
	identity := strings.TrimSpace(payload.Email)
	if identity == "" {
		identity = strings.TrimSpace(payload.Username)
	}
	if !validMetadata(identity) {
		return provider.Account{}, ErrSchema
	}
	tier := standardTier
	subscriptionGrade := 0
	if payload.SVIP.Time > 0 {
		tier = svipTier
		subscriptionGrade = 2
	} else if payload.VIPTime > 0 {
		tier = vipTier
		subscriptionGrade = 1
	}
	// vipInfo grades do not reliably match the tier: a live SVIP account lists
	// its only period as grade 1. Prefer a period whose grade matches the tier,
	// otherwise use the latest listed period. Either way the expiry is an exact
	// server-supplied time, never inferred from day counters.
	var subscriptionEndsAt, latestEndsAt time.Time
	for _, period := range payload.VIPSubscription {
		if period.Grade != 1 && period.Grade != 2 {
			return provider.Account{}, ErrSchema
		}
		if period.EndTime == "" {
			continue
		}
		parsed, err := time.ParseInLocation("2006-01-02 15:04:05", period.EndTime, location)
		if err != nil {
			return provider.Account{}, ErrSchema
		}
		if parsed.After(latestEndsAt) {
			latestEndsAt = parsed.UTC()
		}
		if period.Grade == subscriptionGrade && parsed.After(subscriptionEndsAt) {
			subscriptionEndsAt = parsed.UTC()
		}
	}
	if subscriptionGrade != 0 && subscriptionEndsAt.IsZero() {
		subscriptionEndsAt = latestEndsAt
	}
	active := subscriptionGrade != 0
	if active && !subscriptionEndsAt.After(now) {
		return provider.Account{}, ErrSchema
	}
	return provider.Account{
		UserID: strconv.FormatInt(payload.UserID, 10), Display: provider.RedactAccount(identity), Tier: tier,
		SubscriptionActive: active, SubscriptionEndsAt: subscriptionEndsAt,
	}, nil
}
