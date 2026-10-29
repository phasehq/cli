package proxy

import (
	"net/http"
	"reflect"
	"testing"
)

func TestLowercaseAmazonMetadataHeadersMatchesS3Wire(t *testing.T) {
	header := http.Header{
		"X-Amz-Meta-Owner":             {"claude"},
		"x-amz-meta-project":           {"phase"},
		"X-Amz-Meta-Project":           {"console"},
		"X-Amz-Request-Id":             {"req-1"},
		"Content-Type":                 {"text/plain"},
		"X-Amz-Server-Side-Encryption": {"AES256"},
	}
	LowercaseAmazonMetadataHeaders(header)
	want := http.Header{
		"x-amz-meta-owner":             {"claude"},
		"x-amz-meta-project":           {"phase", "console"},
		"X-Amz-Request-Id":             {"req-1"},
		"Content-Type":                 {"text/plain"},
		"X-Amz-Server-Side-Encryption": {"AES256"},
	}
	if !reflect.DeepEqual(header, want) {
		t.Fatalf("headers = %#v, want %#v", header, want)
	}
	LowercaseAmazonMetadataHeaders(nil)
}
