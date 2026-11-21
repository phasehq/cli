package cmd

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/phasehq/cli/pkg/config"
	"github.com/phasehq/cli/pkg/phase"
	"github.com/phasehq/cli/pkg/util"
	"github.com/phasehq/golang-sdk/v2/phase/crypto"
	"github.com/spf13/cobra"
)

func runWebAuth(cmd *cobra.Command, host string) error {
	// Pick random port
	port := 8002 + rand.Intn(12001)

	// Generate ephemeral keypair
	kp, err := crypto.RandomKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate keypair: %w", err)
	}

	pubKeyHex := hex.EncodeToString(kp.PublicKey[:])
	privKeyHex := hex.EncodeToString(kp.SecretKey[:])

	// Build PAT name
	username := "unknown"
	if u, err := user.Current(); err == nil {
		username = u.Username
	}
	hostname, _ := os.Hostname()
	patName := fmt.Sprintf("%s@%s", username, hostname)

	// Encode payload
	rawData := fmt.Sprintf("%d-%s-%s", port, pubKeyHex, patName)
	encoded := base64.StdEncoding.EncodeToString([]byte(rawData))

	listener, err := listenWebAuth(port)
	if err != nil {
		return fmt.Errorf("failed to start server on port %d: %w", port, err)
	}

	handler, dataCh := webAuthCallback(host, privKeyHex, pubKeyHex)
	server := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	go server.Serve(listener)

	// Print webauth URL
	authURL := fmt.Sprintf("%s/webauth/%s", host, encoded)
	fmt.Fprintf(os.Stderr, "\n  %s\n\n", util.BoldCyanErr(authURL))
	fmt.Fprintf(os.Stderr, "Press %s to open in your browser.\n\n", util.BoldErr("Enter"))

	// Wait for Enter in a goroutine so we can also accept the callback
	go func() {
		buf := make([]byte, 1)
		os.Stdin.Read(buf)
		if err := util.OpenBrowser(authURL); err != nil {
			fmt.Fprintf(os.Stderr, "Could not open browser: %v\n", err)
		}
	}()

	// Wait for webauth reponse
	spinner := util.NewSpinner("Waiting for authentication")
	spinner.Start()
	var received webAuthLogin
	select {
	case received = <-dataCh:
	case <-time.After(5 * time.Minute):
		spinner.Stop()
		server.Close()
		return fmt.Errorf("authentication timed out")
	}

	// Shut down server
	spinner.Stop()
	server.Close()

	authToken := strings.TrimSpace(received.pss)
	userEmail := strings.TrimSpace(received.email)

	// Validate token
	p, err := phase.NewPhase(false, authToken, host)
	if err != nil {
		return fmt.Errorf("invalid token: %w", err)
	}

	if err := phase.Auth(p); err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	// Get user data
	userData, err := phase.Init(p)
	if err != nil {
		return fmt.Errorf("failed to fetch user data: %w", err)
	}

	accountID, err := phase.AccountID(userData)
	if err != nil {
		return err
	}

	var orgID, orgName *string
	if userData.Organisation != nil {
		orgID = &userData.Organisation.ID
		orgName = &userData.Organisation.Name
	}

	var wrappedKeyShare *string
	if userData.WrappedKeyShare != "" {
		wrappedKeyShare = &userData.WrappedKeyShare
	}

	userConfig := config.UserConfig{
		Host:             host,
		ID:               accountID,
		Email:            userEmail,
		OrganizationID:   orgID,
		OrganizationName: orgName,
		WrappedKeyShare:  wrappedKeyShare,
	}
	if err := saveUserLogin(cmd, userConfig, authToken); err != nil {
		return err
	}

	fmt.Println(util.BoldGreen("✅ Authentication successful."))
	return nil
}

// listenWebAuth listens for the callback on loopback only: the Console's page
// posts to 127.0.0.1, so nothing on the network need reach it.
func listenWebAuth(port int) (net.Listener, error) {
	return net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
}

// webAuthBodyLimit bounds a callback body; the real one is two short
// ciphertexts.
const webAuthBodyLimit = 64 << 10

type webAuthLogin struct{ email, pss string }

// webAuthCallback serves the Console's callback. Only a body that decrypts
// with this login's key ends the wait; anything else is refused and the CLI
// keeps waiting, so a stray or hostile POST cannot cancel the login.
func webAuthCallback(host, privKeyHex, pubKeyHex string) (http.Handler, <-chan webAuthLogin) {
	type authData struct {
		Email string `json:"email"`
		PSS   string `json:"pss"`
	}
	dataCh := make(chan webAuthLogin, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", host)
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method != "POST" {
			return
		}
		var data authData
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, webAuthBodyLimit)).Decode(&data); err != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		email, emailErr := crypto.DecryptAsymmetric(data.Email, privKeyHex, pubKeyHex)
		pss, pssErr := crypto.DecryptAsymmetric(data.PSS, privKeyHex, pubKeyHex)
		if emailErr != nil || pssErr != nil {
			http.Error(w, "invalid request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "Success: CLI authentication complete",
		})
		select {
		case dataCh <- webAuthLogin{email: email, pss: pss}:
		default:
		}
	})
	return mux, dataCh
}
