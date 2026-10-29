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

func TestRiskAndAddressClassification(t *testing.T) {
	for _, addr := range []string{"127.0.0.1", "127.0.1.1", "::1", "[::1]", "[::1%lo0]", "localhost"} {
		if isPublicAddr(addr) {
			t.Errorf("loopback misclassified: %s", addr)
		}
	}
	for _, addr := range []string{"0.0.0.0", "::", "*", "192.0.2.1"} {
		if !isPublicAddr(addr) {
			t.Errorf("nonloopback misclassified: %s", addr)
		}
	}
	for _, port := range []int{3306, 33060, 5432, 6379, 27017, 9200, 9300, 2375, 2376} {
		if risk, _ := AssessRisk(port, true, "service"); risk != RiskDanger {
			t.Errorf("missing risk for %d", port)
		}
	}
	for _, proc := range []string{"postgres", "redis", "mysql", "mongo"} {
		if risk, _ := AssessRisk(1234, true, proc); risk != RiskDanger {
			t.Errorf("missing risk for %s", proc)
		}
	}
	if risk, _ := AssessRisk(1234, true, "docker-proxy"); risk != RiskWarn {
		t.Fatal("proxy risk")
	}
	if risk, _ := AssessRisk(1234, true, "service"); risk != RiskWarn {
		t.Fatal("unknown service risk")
	}
	report := &AuditReport{Ports: []PortItem{{Port: 3306, Risk: RiskDanger, Process: "mysql"}, {Port: 22, Risk: RiskWarn}}, DockerInstalled: true, SSH: SSHSummary{PasswordAuth: "yes"}}
	report.Evaluate()
	if report.Score < 0 || report.Score >= 100 || len(report.Suggestions) == 0 {
		t.Fatal("risk score")
	}
	report.Ports = make([]PortItem, 20)
	for i := range report.Ports {
		report.Ports[i].Risk = RiskDanger
	}
	report.Evaluate()
	if report.Score != 0 {
		t.Fatal("score below zero")
	}
}
