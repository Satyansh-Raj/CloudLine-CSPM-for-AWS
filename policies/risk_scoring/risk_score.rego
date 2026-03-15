package aws.risk_scoring

severity_weights := {
	"critical": 100,
	"high": 80,
	"medium": 50,
	"low": 20,
}

dimension_weights := {
	"severity": 0.30,
	"exploitability": 0.25,
	"blast_radius": 0.20,
	"data_sensitivity": 0.15,
	"compliance_impact": 0.10,
}

# Full 5D scoring (when all dimensions provided)
risk_score_5d(violation) := round(score) if {
	s := severity_weights[violation.severity]
	e := object.get(violation, "exploitability", 0)
	b := object.get(violation, "blast_radius", 0)
	d := object.get(violation, "data_sensitivity", 0)
	c := object.get(violation, "compliance_impact", 0)
	score := ((((s * 0.30) + (e * 0.25)) + (b * 0.20)) + (d * 0.15)) + (c * 0.10)
}

# Severity-only fallback (backward compat)
risk_score(violation) := score if {
	s := severity_weights[violation.severity]
	score := s
}

default risk_score(_) := 0
