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
	"github.com/phasehq/golang-sdk/phase/crypto"
	"github.com/spf13/cobra"
)

func runWebAuth(cmd *cobra.Command, host string) error {
	// Pick random port
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	port := 8000 + rng.Intn(12001)

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

	// Open browser
	authURL := fmt.Sprintf("%s/webauth/%s", host, encoded)
	fmt.Fprintf(os.Stderr, "Opening browser for authentication...\n")
	if err := util.OpenBrowser(authURL); err != nil {
		fmt.Fprintf(os.Stderr, "Please open this URL in your browser:\n%s\n", authURL)
	}

	// Wait for data
	fmt.Fprintf(os.Stderr, "Waiting for authentication...\n")
	var received authData
	select {
	case received = <-dataCh:
	case <-time.After(5 * time.Minute):
		server.Close()
		return fmt.Errorf("authentication timed out")
	}

	// Shut down server
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
	if userData.OfflineEnabled && userData.WrappedKeyShare != "" {
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
