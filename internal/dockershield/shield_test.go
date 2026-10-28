package dockershield

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShieldManagerUFW(t *testing.T) {
	tmpDir := t.TempDir()
	rulesFile := filepath.Join(tmpDir, "after.rules")
	initialContent := "# Default UFW rules\nCOMMIT\n"
	if err := os.WriteFile(rulesFile, []byte(initialContent), 0644); err != nil {
		t.Fatalf("failed to create dummy rules file: %v", err)
	}

	sm := &ShieldManager{AfterRulesPath: rulesFile}
	ctx := context.Background()

	// Initial check
	enabled, err := sm.IsEnabled(ctx)
	if err != nil || enabled {
		t.Fatalf("expected disabled initially, got %v %v", enabled, err)
	}

	// Enable
	if err := sm.enableUFW(ctx); err != nil {
		t.Fatalf("enableUFW failed: %v", err)
	}

	enabled, err = sm.IsEnabled(ctx)
	if err != nil || !enabled {
		t.Fatalf("expected enabled after enableUFW, got %v %v", enabled, err)
	}

	// Disable
	if err := sm.Disable(ctx); err != nil {
		t.Fatalf("disable failed: %v", err)
	}

	enabled, err = sm.IsEnabled(ctx)
	if err != nil || enabled {
		t.Fatalf("expected disabled after Disable, got %v %v", enabled, err)
	}

	finalContent, _ := os.ReadFile(rulesFile)
	if strings.Contains(string(finalContent), UFWRulesTagBegin) {
		t.Fatalf("found leftover tags in rules file")
	}
}
