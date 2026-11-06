package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kdlbs/kandev/pluginsdk"
	"kandev-security/internal/reports"
)

// This optional HTTP bridge exercises curl against the plugin handler and real
// SQLite. Kandev's authentication/gRPC gateway is covered by the host contract,
// not started by this test. Opt in where binding a loopback socket is allowed.
func TestCurlWebhookUpload(t *testing.T) {
	if os.Getenv("KANDEV_SECURITY_CURL_SMOKE") != "1" {
		t.Skip("set KANDEV_SECURITY_CURL_SMOKE=1 to enable the curl HTTP smoke test")
	}
	curl, err := exec.LookPath("curl")
	if err != nil {
		t.Fatal(err)
	}
	p := testPlugin(t)
	p.SetHost(testWorkspaceHost{reader: testWorkspaceReader{}})
	token, err := p.store.CreateUploadToken(context.Background(), "ws", "issuer", "curl")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, reports.MaxWebhookBytes))
		if err != nil {
			http.Error(w, "body too large", 413)
			return
		}
		headers := map[string]string{}
		for k, v := range r.Header {
			headers[k] = strings.Join(v, ", ")
		}
		response, err := p.HandleWebhook(r.Context(), &pluginsdk.WebhookRequest{WebhookKey: "upload", Method: r.Method, Headers: headers, Query: r.URL.RawQuery, Body: body})
		if err != nil {
			http.Error(w, "plugin failed", 500)
			return
		}
		for k, v := range response.Headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(int(response.Status))
		w.Write(response.Body)
	}))
	defer server.Close()
	raw := []byte(strings.Replace(webhookSample, "Finding", "Finding é😀", 1))
	file := filepath.Join(t.TempDir(), "scan.sarif")
	if err = os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(curl, "--silent", "--show-error", "--fail-with-body", "--request", "POST", server.URL+"/api/plugins/kandev-security/webhooks/upload", "-H", "Authorization: Bearer test-pat", "-H", "X-Security-Token: "+token.Secret, "-H", "X-Security-Filename: scan.sarif", "-H", "Content-Type: application/sarif+json", "--data-binary", "@"+file).CombinedOutput()
	if err != nil {
		t.Fatalf("curl failed: %v: %s", err, output)
	}
	var imported reports.ImportResult
	if err = json.Unmarshal(output, &imported); err != nil {
		t.Fatal(err)
	}
	if imported.Report.WorkspaceID != "ws" || imported.Report.ActorID != "issuer" {
		t.Fatalf("incorrect ownership: %+v", imported.Report)
	}
	source, err := p.store.Source(context.Background(), "ws", imported.Report.ID, 0)
	if err != nil {
		t.Fatal(err)
	}
	original, err := base64.StdEncoding.DecodeString(source.Data)
	if err != nil || !bytes.Equal(original, raw) {
		t.Fatal("curl upload changed file bytes")
	}
}
