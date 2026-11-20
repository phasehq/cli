package proxy

import (
	"net/http"
	"strings"
)

// LowercaseAmazonMetadataHeaders restores the header-name casing S3 uses for
// user metadata. Go canonicalizes parsed header names (X-Amz-Meta-Owner), and
// AWS SDKs build the Metadata map from the wire name after the prefix, so a
// client would see "Owner" instead of "owner". S3 itself sends these names in
// lowercase; writing them back that way keeps metadata keys identical to a
// direct connection.
func LowercaseAmazonMetadataHeaders(header http.Header) {
	const prefix = "x-amz-meta-"
	for name, values := range header {
		lower := strings.ToLower(name)
		if !strings.HasPrefix(lower, prefix) || lower == name {
			continue
		}
		header[lower] = append(header[lower], values...)
		delete(header, name)
	}
}
