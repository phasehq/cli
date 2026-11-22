package aiproxy

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/klauspost/compress/zstd"
)

const (
	// maxLeakBody is the most of a request body the proxy holds to inspect. A
	// longer body is forwarded as it was. It is above the 32 MB Anthropic
	// accepts in one request, so a body a provider would take is read.
	maxLeakBody = 40 << 20
	// maxLeakDecoded bounds what a compressed body may inflate to, so a small
	// bomb costs little.
	maxLeakDecoded = 64 << 20
)

var errLeakDecodedTooLarge = errors.New("the decoded body is over the size limit")

// zstdDecoder is shared: DecodeAll is safe for concurrent use, and building a
// decoder per request costs more than most of the bodies it would read.
var zstdDecoder = sync.OnceValues(func() (*zstd.Decoder, error) {
	return zstd.NewReader(nil, zstd.WithDecoderMaxMemory(maxLeakDecoded), zstd.WithDecoderConcurrency(0))
})

// leakEncoding names a body's Content-Encoding the way the decoder and the
// encoder agree on. An encoding the proxy cannot undo is returned as it is, with
// ok false; a list of several encodings is not undone either.
func leakEncoding(header string) (string, bool) {
	encoding := strings.ToLower(strings.TrimSpace(header))
	switch encoding {
	case "", "identity":
		return "identity", true
	case "gzip", "x-gzip":
		return "gzip", true
	case "deflate":
		return "deflate", true
	case "zstd":
		return "zstd", true
	}
	return encoding, false
}

// deflateRaw is a deflate body sent without the zlib wrapper HTTP asks for.
// It is re-encoded the same way, since the server reads what the client sent.
const deflateRaw = "deflate-raw"

// decodeLeakBody undoes a body's Content-Encoding. Only the declared encoding
// counts: guessing from magic bytes could decode a body the provider reads as
// it is. It returns the encoding to write the body back with.
func decodeLeakBody(body []byte, encoding string) ([]byte, string, error) {
	var reader io.Reader
	switch encoding {
	case "identity":
		return body, encoding, nil
	case "zstd":
		decoder, err := zstdDecoder()
		if err != nil {
			return nil, encoding, err
		}
		decoded, err := decoder.DecodeAll(body, nil)
		if err != nil {
			return nil, encoding, err
		}
		if len(decoded) > maxLeakDecoded {
			return nil, encoding, errLeakDecodedTooLarge
		}
		return decoded, encoding, nil
	case "gzip":
		gz, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return nil, encoding, err
		}
		defer gz.Close()
		reader = gz
	case "deflate":
		// HTTP's deflate is zlib-wrapped; some clients send raw deflate anyway.
		if z, err := zlib.NewReader(bytes.NewReader(body)); err == nil {
			defer z.Close()
			reader = z
		} else {
			reader, encoding = flate.NewReader(bytes.NewReader(body)), deflateRaw
		}
	default:
		return nil, encoding, fmt.Errorf("no decoder for %s", encoding)
	}
	decoded, err := io.ReadAll(io.LimitReader(reader, maxLeakDecoded+1))
	if err != nil {
		return nil, encoding, err
	}
	if len(decoded) > maxLeakDecoded {
		return nil, encoding, errLeakDecodedTooLarge
	}
	return decoded, encoding, nil
}

// encodeLeakBody compresses a rewritten body the way the original arrived.
func encodeLeakBody(body []byte, encoding string) ([]byte, error) {
	var buffer bytes.Buffer
	var writer io.WriteCloser
	switch encoding {
	case "identity":
		return body, nil
	case "zstd":
		encoder, err := zstd.NewWriter(nil)
		if err != nil {
			return nil, err
		}
		defer encoder.Close()
		return encoder.EncodeAll(body, nil), nil
	case "gzip":
		writer = gzip.NewWriter(&buffer)
	case "deflate":
		writer = zlib.NewWriter(&buffer)
	case deflateRaw:
		raw, err := flate.NewWriter(&buffer, flate.DefaultCompression)
		if err != nil {
			return nil, err
		}
		writer = raw
	default:
		return nil, fmt.Errorf("no encoder for %s", encoding)
	}
	if _, err := writer.Write(body); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
