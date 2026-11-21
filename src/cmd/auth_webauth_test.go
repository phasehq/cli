package cmd

import (
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/phasehq/golang-sdk/v2/phase/crypto"
)

// A POST that does not decrypt with this login's key, or is oversized, is
// refused and the login keeps waiting for the Console's real callback.
func TestWebAuthCallbackKeepsWaitingAfterABadPost(t *testing.T) {
	keyPair, err := crypto.RandomKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey := hex.EncodeToString(keyPair.PublicKey[:]), hex.EncodeToString(keyPair.SecretKey[:])
	handler, logins := webAuthCallback("https://console.phase.invalid", privateKey, publicKey)
	post := func(body string) int {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
		return recorder.Code
	}

	for _, body := range []string{
		`{"email":"x","pss":"y"}`,
		`not json`,
		`{"email":"` + strings.Repeat("a", webAuthBodyLimit) + `"}`,
	} {
		if code := post(body); code != http.StatusBadRequest {
			t.Fatalf("a bad POST got %d", code)
		}
		select {
		case login := <-logins:
			t.Fatalf("a bad POST ended the wait: %+v", login)
		default:
		}
	}

	email, _ := crypto.EncryptAsymmetric("person@example.invalid", publicKey)
	pss, _ := crypto.EncryptAsymmetric("pss_user:v1:fake", publicKey)
	body, _ := json.Marshal(map[string]string{"email": email, "pss": pss})
	if code := post(string(body)); code != http.StatusOK {
		t.Fatalf("the real callback got %d", code)
	}
	select {
	case login := <-logins:
		if login.email != "person@example.invalid" || login.pss != "pss_user:v1:fake" {
			t.Fatalf("login = %+v", login)
		}
	default:
		t.Fatal("the real callback did not end the wait")
	}
	// A second POST after the login must not block the handler.
	if code := post(string(body)); code != http.StatusOK {
		t.Fatalf("a repeated callback got %d", code)
	}
}

func TestWebAuthListensOnLoopbackOnly(t *testing.T) {
	listener, err := listenWebAuth(0)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || !address.IP.IsLoopback() {
		t.Fatalf("listening on %v, want loopback only", listener.Addr())
	}
}
