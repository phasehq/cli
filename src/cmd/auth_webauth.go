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
	"github.com/phasehq/cli/pkg/keyring"
	"github.com/phasehq/cli/pkg/phase"
	"github.com/phasehq/cli/pkg/util"
	"github.com/phasehq/golang-sdk/v2/phase/crypto"
	"github.com/spf13/cobra"
)

// webAuthPayload is the request payload the Console webauth page parses. It is sent
// as base64(JSON) in the webauth URL. Lifetime is the requested token lifetime in
// seconds; when 0 it is omitted and the token never expires.
type webAuthPayload struct {
	Port      int    `json:"port"`
	PublicKey string `json:"publicKey"`
	Name      string `json:"name"`
	Lifetime  int64  `json:"lifetime,omitempty"`
}

// resolveTokenName returns the requested token name: the trimmed flag value when
// set, otherwise the default username@hostname.
func resolveTokenName(flagValue, username, hostname string) string {
	if name := strings.TrimSpace(flagValue); name != "" {
		return name
	}
	return fmt.Sprintf("%s@%s", username, hostname)
}

// encodeWebAuthPayload serializes the webauth request payload as base64(JSON).
func encodeWebAuthPayload(port int, pubKeyHex, name string, lifetimeSeconds int64) (string, error) {
	rawData, err := json.Marshal(webAuthPayload{
		Port:      port,
		PublicKey: pubKeyHex,
		Name:      name,
		Lifetime:  lifetimeSeconds,
	})
	if err != nil {
		return "", fmt.Errorf("failed to encode webauth payload: %w", err)
	}
	return base64.StdEncoding.EncodeToString(rawData), nil
}

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

	// Build PAT name (default username@hostname, overridable via --token-name)
	username := "unknown"
	if u, err := user.Current(); err == nil {
		username = u.Username
	}
	hostname, _ := os.Hostname()
	tokenNameFlag, _ := cmd.Flags().GetString("token-name")
	patName := resolveTokenName(tokenNameFlag, username, hostname)

	// Parse the requested token lifetime (default: never expires)
	lifetimeStr, _ := cmd.Flags().GetString("token-lifetime")
	lifetimeSeconds, err := util.ParseTokenLifetime(lifetimeStr)
	if err != nil {
		return err
	}

	// Encode payload as base64(JSON): { port, publicKey, name, lifetime? }
	encoded, err := encodeWebAuthPayload(port, pubKeyHex, patName, lifetimeSeconds)
	if err != nil {
		return err
	}

	// Channel to receive auth data
	type authData struct {
		Email string `json:"email"`
		PSS   string `json:"pss"`
	}
	dataCh := make(chan authData, 1)

	// Create listener
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("failed to start server on port %d: %w", port, err)
	}

	// Set up HTTP handler
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		origin := host
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		if r.Method == "POST" {
			var data authData
			if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"status": "Success: CLI authentication complete",
			})
			dataCh <- data
		}
	})

	server := &http.Server{Handler: mux}
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
	var received authData
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

	// Decrypt email and PSS
	decryptedEmail, err := crypto.DecryptAsymmetric(received.Email, privKeyHex, pubKeyHex)
	if err != nil {
		return fmt.Errorf("failed to decrypt email: %w", err)
	}

	decryptedPSS, err := crypto.DecryptAsymmetric(received.PSS, privKeyHex, pubKeyHex)
	if err != nil {
		return fmt.Errorf("failed to decrypt token: %w", err)
	}

	authToken := strings.TrimSpace(decryptedPSS)
	userEmail := strings.TrimSpace(decryptedEmail)

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

	// Save credentials to keyring
	tokenSavedInKeyring := true
	if err := keyring.SetCredentials(accountID, authToken); err != nil {
		tokenSavedInKeyring = false
	}

	// Build user config
	userConfig := config.UserConfig{
		Host:             host,
		ID:               accountID,
		Email:            userEmail,
		OrganizationID:   orgID,
		OrganizationName: orgName,
		WrappedKeyShare:  wrappedKeyShare,
	}
	if !tokenSavedInKeyring {
		userConfig.Token = authToken
	}

	// Save to config
	if err := config.AddUser(userConfig); err != nil {
		return fmt.Errorf("failed to save config: %w", err)
	}

	fmt.Println(util.BoldGreen("✅ Authentication successful."))
	return nil
}
