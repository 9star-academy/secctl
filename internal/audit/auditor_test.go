package audit

import (
	"context"
	"testing"
)

func TestAssessRisk(t *testing.T) {
	// Localhost should always be safe
	risk, _ := AssessRisk(3306, false, "mysqld")
	if risk != RiskSafe {
		t.Fatalf("expected SAFE for local addr, got %s", risk)
	}

	// Exposed database should be DANGER
	risk, _ = AssessRisk(3306, true, "mysqld")
	if risk != RiskDanger {
		t.Fatalf("expected DANGER for exposed 3306, got %s", risk)
	}

	// Exposed Redis should be DANGER
	risk, _ = AssessRisk(6379, true, "redis-server")
	if risk != RiskDanger {
		t.Fatalf("expected DANGER for exposed 6379, got %s", risk)
	}

	// Standard web ports should be INFO
	risk, _ = AssessRisk(443, true, "nginx")
	if risk != RiskInfo {
		t.Fatalf("expected INFO for 443, got %s", risk)
	}

	// Default SSH should be WARN
	risk, _ = AssessRisk(22, true, "sshd")
	if risk != RiskWarn {
		t.Fatalf("expected WARN for 22, got %s", risk)
	}
}

func TestAuditorLocal(t *testing.T) {
	auditor := NewAuditor()
	report, err := auditor.Audit(context.Background())
	if err != nil {
		t.Fatalf("Audit failed: %v", err)
	}
	if report.Score < 0 || report.Score > 100 {
		t.Fatalf("invalid score: %d", report.Score)
	}
}
