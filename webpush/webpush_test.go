package webpush

import "testing"

func TestEndpointHost(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		want     string
	}{
		{
			name:     "fcm-style endpoint",
			endpoint: "https://fcm.googleapis.com/fcm/send/abc123devicetoken",
			want:     "fcm.googleapis.com",
		},
		{
			name:     "mozilla autopush-style endpoint",
			endpoint: "https://updates.push.services.mozilla.com/wpush/v2/xyz789subscriptionid",
			want:     "updates.push.services.mozilla.com",
		},
		{
			name:     "invalid url",
			endpoint: "://not a url",
			want:     "",
		},
		{
			name:     "empty string",
			endpoint: "",
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EndpointHost(tt.endpoint); got != tt.want {
				t.Errorf("EndpointHost(%q) = %q, want %q", tt.endpoint, got, tt.want)
			}
		})
	}
}

func TestIsGone(t *testing.T) {
	for status, want := range map[int]bool{201: false, 400: false, 404: true, 410: true, 429: false} {
		if got := IsGone(status); got != want {
			t.Errorf("IsGone(%d) = %v, want %v", status, got, want)
		}
	}
}

func TestVAPIDConfigEnabled(t *testing.T) {
	if (VAPIDConfig{PublicKey: "a", PrivateKey: "b"}).Enabled() {
		t.Error("missing subject should be disabled")
	}
	if !(VAPIDConfig{PublicKey: "a", PrivateKey: "b", Subject: "mailto:x@y.z"}).Enabled() {
		t.Error("complete config should be enabled")
	}
}
