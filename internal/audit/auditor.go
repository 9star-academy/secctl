package audit

import (
	"context"
	"fmt"
	"strings"
)

// RiskLevel represents the risk level of an open port.
type RiskLevel string

const (
	RiskSafe   RiskLevel = "SAFE"
	RiskInfo   RiskLevel = "INFO"
	RiskWarn   RiskLevel = "WARN"
	RiskDanger RiskLevel = "DANGER"
)

// PortItem represents a listening port.
type PortItem struct {
	Protocol    string    `json:"protocol"`
	Address     string    `json:"address"`
	Port        int       `json:"port"`
	PID         int       `json:"pid"`
	Process     string    `json:"process"`
	IsPublic    bool      `json:"is_public"`
	Risk        RiskLevel `json:"risk"`
	Description string    `json:"description"`
}

// SSHSummary represents a summary of SSH configuration.
type SSHSummary struct {
	Port           int    `json:"port"`
	PasswordAuth   string `json:"password_auth"` // "yes", "no", "unknown"
	PermitRoot     string `json:"permit_root"`   // "yes", "no", "prohibit-password"
	AuthorizedKeys int    `json:"authorized_keys_count"`
}

// AuditReport holds the full security assessment.
type AuditReport struct {
	Ports               []PortItem `json:"ports"`
	FirewallActive      bool       `json:"firewall_active"`
	FirewallType        string     `json:"firewall_type"` // "ufw", "iptables", "none", "macos-pf"
	SSH                 SSHSummary `json:"ssh"`
	DockerInstalled     bool       `json:"docker_installed"`
	DockerShieldEnabled bool       `json:"docker_shield_enabled"`
	Score               int        `json:"score"` // 0-100
	Suggestions         []string   `json:"suggestions"`
}

// AssessRisk evaluates risk for an open port and process.
func AssessRisk(port int, isPublic bool, process string) (RiskLevel, string) {
	if !isPublic {
		return RiskSafe, "仅本地监听 (Loopback)"
	}

	pLower := strings.ToLower(process)

	// High-risk database / cache ports exposed to public!
	switch port {
	case 3306, 33060:
		return RiskDanger, "MySQL 暴露公网！极易遭到字典爆破与勒索"
	case 5432:
		return RiskDanger, "PostgreSQL 暴露公网！建议限制内网或关闭公网监听"
	case 6379:
		return RiskDanger, "Redis 暴露公网！若无密码或弱密码存在严重提权风险"
	case 27017:
		return RiskDanger, "MongoDB 暴露公网！存在未授权访问勒索风险"
	case 9200, 9300:
		return RiskDanger, "Elasticsearch 暴露公网！"
	case 2375, 2376:
		return RiskDanger, "Docker Remote API 暴露公网！存在直接 root 逃逸提权风险"
	}

	if strings.Contains(pLower, "redis") || strings.Contains(pLower, "postgres") ||
		strings.Contains(pLower, "mysql") || strings.Contains(pLower, "mongo") {
		return RiskDanger, "数据库/缓存服务监听公网！"
	}

	// Web ports (normal)
	if port == 80 || port == 443 {
		return RiskInfo, "标准 Web 端口 (正常对外服务)"
	}

	// SSH port
	if port == 22 {
		return RiskWarn, "SSH 默认端口 22 暴露公网，常年承受全球僵尸网络暴力扫描"
	}

	// Docker proxy warnings
	if strings.Contains(pLower, "docker-proxy") {
		return RiskWarn, "Docker 容器映射端口暴露公网，注意确认是否已受防火墙保护"
	}

	return RiskWarn, fmt.Sprintf("公网开放端口 (%s)", process)
}

// Auditor gathers system security data.
type Auditor interface {
	Audit(ctx context.Context) (*AuditReport, error)
}
