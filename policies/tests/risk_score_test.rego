package aws.risk_scoring_test

import data.aws.risk_scoring

# -- Severity-only fallback tests (backward compat) --

test_critical_score if {
	score := risk_scoring.risk_score({"severity": "critical"})
	score == 100
}

test_high_score if {
	score := risk_scoring.risk_score({"severity": "high"})
	score == 80
}

test_medium_score if {
	score := risk_scoring.risk_score({"severity": "medium"})
	score == 50
}

test_low_score if {
	score := risk_scoring.risk_score({"severity": "low"})
	score == 20
}

test_unknown_score if {
	score := risk_scoring.risk_score({"severity": "unknown"})
	score == 0
}

# -- 5D scoring tests --

test_5d_all_dimensions if {
	score := risk_scoring.risk_score_5d({
		"severity": "critical",
		"exploitability": 100,
		"blast_radius": 100,
		"data_sensitivity": 100,
		"compliance_impact": 100,
	})
	score == 100
}

test_5d_severity_only if {
	score := risk_scoring.risk_score_5d({"severity": "high"})

	# 80*0.30 + 0 + 0 + 0 + 0 = 24
	score == 24
}

test_5d_mixed_dimensions if {
	score := risk_scoring.risk_score_5d({
		"severity": "critical",
		"exploitability": 60,
		"blast_radius": 40,
		"data_sensitivity": 20,
		"compliance_impact": 10,
	})

	# 100*0.30 + 60*0.25 + 40*0.20 + 20*0.15 + 10*0.10
	# = 30 + 15 + 8 + 3 + 1 = 57
	score == 57
}

test_5d_zero_severity if {
	score := risk_scoring.risk_score_5d({
		"severity": "low",
		"exploitability": 0,
		"blast_radius": 0,
		"data_sensitivity": 0,
		"compliance_impact": 0,
	})

	# 20*0.30 = 6
	score == 6
}
