package main

import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "io"
    "log"
    "net/http"
    "os/exec"
	"os"
)

var webhookSecret = os.Getenv("WEBHOOK_SECRET")
const (
    repoPath      = "/var/www/thenickmonaco.com"
)

func verifySignature(signature string, body []byte) bool {
    mac := hmac.New(sha256.New, []byte(webhookSecret))
    mac.Write(body)
    expectedMAC := mac.Sum(nil)
    expectedSignature := "sha256=" + hex.EncodeToString(expectedMAC)
    return hmac.Equal([]byte(expectedSignature), []byte(signature))
}

func handler(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
        return
    }

    signature := r.Header.Get("X-Hub-Signature-256")
    if signature == "" {
        http.Error(w, "Missing signature", http.StatusForbidden)
        return
    }

    body, err := io.ReadAll(r.Body)
    if err != nil {
        http.Error(w, "Could not read body", http.StatusInternalServerError)
        return
    }
    defer r.Body.Close()

    if !verifySignature(signature, body) {
        http.Error(w, "Invalid signature", http.StatusForbidden)
        return
    }

    // Run git pull
    cmd := exec.Command("git", "-C", repoPath, "pull")
    output, err := cmd.CombinedOutput()
    if err != nil {
        log.Printf("git pull failed: %v, output: %s", err, string(output))
        http.Error(w, "git pull failed", http.StatusInternalServerError)
        return
    }

    log.Printf("git pull successful: %s", string(output))
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Updated"))
}

func main() {
    http.HandleFunc("/github-webhook", handler)
    log.Println("Starting server on :5000")
    err := http.ListenAndServe(":5000", nil)
    if err != nil {
        log.Fatalf("Server failed: %v", err)
    }
}

