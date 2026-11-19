package approvalapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

// WebhookTolerance is how far a webhook signature's timestamp may be from now.
const WebhookTolerance = 5 * time.Minute

// SignWebhook is the Gatecrasher-Signature header value for body sent at t.
func SignWebhook(secret, body []byte, t time.Time) string {
	ts := strconv.FormatInt(t.Unix(), 10)
	return "t=" + ts + ",v1=" + hex.EncodeToString(webhookMAC(secret, ts, body))
}

// VerifyWebhook checks a Gatecrasher-Signature header against body, within
// WebhookTolerance of now.
func VerifyWebhook(secret, body []byte, header string, now time.Time) error {
	var ts, sig string
	for part := range strings.SplitSeq(header, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch k {
		case "t":
			ts = v
		case "v1":
			sig = v
		}
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || sig == "" {
		return errors.New("webhook: malformed signature")
	}
	if d := now.Sub(time.Unix(sec, 0)); d > WebhookTolerance || d < -WebhookTolerance {
		return errors.New("webhook: signature too old")
	}
	got, err := hex.DecodeString(sig)
	if err != nil || !hmac.Equal(got, webhookMAC(secret, ts, body)) {
		return errors.New("webhook: bad signature")
	}
	return nil
}

func webhookMAC(secret []byte, ts string, body []byte) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(ts + "."))
	m.Write(body)
	return m.Sum(nil)
}
