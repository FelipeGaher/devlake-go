// Package webpush sends Web Push notifications (VAPID) to a batch of browser
// subscriptions, with delivery settings that hold up on real Android devices,
// and logs one accesslog line per attempt.
package webpush

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	wp "github.com/SherClockHolmes/webpush-go"

	"github.com/FelipeGaher/devlake-go/accesslog"
)

// TTLSeconds is how long the push service keeps an undelivered message. With
// a short TTL a message deferred by Android Doze silently expires.
const TTLSeconds = 3600

// VAPIDConfig signs messages. Callers should only send when Enabled.
type VAPIDConfig struct {
	PublicKey  string
	PrivateKey string
	Subject    string // "mailto:..." or an https URL
}

// Enabled reports whether all three fields are set.
func (c VAPIDConfig) Enabled() bool {
	return c.PublicKey != "" && c.PrivateKey != "" && c.Subject != ""
}

// Subscription is one browser push subscription (PushSubscription.toJSON()).
type Subscription struct {
	Endpoint string
	P256dh   string
	Auth     string
}

// GoneFunc is called when the push service reports a subscription as
// permanently dead (404/410), so the caller can delete it.
type GoneFunc func(ctx context.Context, endpoint string) error

// Send delivers payload to every subscription in subs, which the caller has
// already batch-loaded for its whole recipient list (one query per fan-out,
// not one per recipient). Uses Urgency: High and a 1-hour TTL: with default
// urgency/TTL, Android Doze defers or drops messages to a closed app even
// though the push service answers 201. A 404/410 response calls onGone
// (may be nil). userID is only used for logging. Errors are logged, not
// returned: one bad subscription must not stop the rest of the fan-out.
func Send(ctx context.Context, vapid VAPIDConfig, userID int64, subs []Subscription, payload []byte, onGone GoneFunc) {
	for _, sub := range subs {
		start := time.Now()
		resp, err := wp.SendNotificationWithContext(ctx, payload, &wp.Subscription{
			Endpoint: sub.Endpoint,
			Keys:     wp.Keys{P256dh: sub.P256dh, Auth: sub.Auth},
		}, &wp.Options{
			Subscriber:      vapid.Subject,
			VAPIDPublicKey:  vapid.PublicKey,
			VAPIDPrivateKey: vapid.PrivateKey,
			Urgency:         wp.UrgencyHigh,
			TTL:             TTLSeconds,
		})
		duration := time.Since(start)

		// statusCode stays 0 when no HTTP response was received (timeout,
		// DNS failure); the raw Go error goes to slog since the fixed
		// access-log schema has no field for it.
		statusCode := 0
		if err != nil {
			slog.ErrorContext(ctx, "webpush: send failed", "user_id", userID, "error", err)
		} else {
			statusCode = resp.StatusCode
			resp.Body.Close()
		}

		accesslog.Write(accesslog.Entry{
			Type:       accesslog.TypeOutgoing,
			Timestamp:  start.UTC().Format(accesslog.TimeFormat),
			HTTPMethod: http.MethodPost,
			RequestURI: EndpointHost(sub.Endpoint),
			StatusCode: statusCode,
			BytesSent:  len(payload),
			DurationMs: float64(duration.Microseconds()) / 1000.0,
			UserID:     userID,
		})

		if err == nil && IsGone(statusCode) && onGone != nil {
			if err := onGone(ctx, sub.Endpoint); err != nil {
				slog.ErrorContext(ctx, "webpush: delete dead subscription failed", "user_id", userID, "error", err)
			}
		}
	}
}

// IsGone reports whether a push-service status means the subscription is
// permanently invalid.
func IsGone(status int) bool {
	return status == http.StatusNotFound || status == http.StatusGone
}

// EndpointHost returns only the host of a subscription endpoint (e.g.
// "fcm.googleapis.com"). The full URL's path is a per-device credential and
// must not be logged.
func EndpointHost(endpoint string) string {
	u, err := url.Parse(endpoint)
	if err != nil {
		return ""
	}
	return u.Host
}
