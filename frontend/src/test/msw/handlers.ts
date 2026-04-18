import { http, HttpResponse } from "msw";
import type {
  ComplianceScore,
  HealthResponse,
  Violation,
  DriftAlertsResponse,
  RiskSummary,
  RiskScoresResponse,
} from "@/types";

const BASE = "/api";

export const mockHealth: HealthResponse = {
  status: "ok",
  service: "cloudline",
  version: "0.1.0",
};

export const mockCompliance: ComplianceScore = {
  total_checks: 20,
  passed: 16,
  failed: 3,
  total_violations: 4,
  errors: 0,
  skipped: 1,
  score_percent: 80,
  by_domain: {
    identity_access: {
      total: 5,
      passed: 4,
      failed: 1,
      score_percent: 80,
    },
    data_protection: {
      total: 5,
      passed: 3,
      failed: 1,
      score_percent: 60,
    },
  },
  by_severity: {
    critical: 1,
    high: 1,
    medium: 1,
    low: 0,
  },
};

export const mockViolations: Violation[] = [
  {
    check_id: "s3_block_public_acls",
    status: "alarm",
    severity: "critical",
    reason: "S3 bucket has public access",
    resource: "arn:aws:s3:::public-bucket",
    domain: "data_protection",
    compliance: {
      cis_aws: ["2.1.1"],
      nist_800_53: ["AC-3"],
      pci_dss: ["1.3.6"],
      hipaa: ["164.312(a)(1)"],
      soc2: ["CC6.1"],
    },
    remediation_id: "REM_s3_01",
  },
  {
    check_id: "ec2_no_open_ssh",
    status: "alarm",
    severity: "high",
    reason: "Security group allows 0.0.0.0/0 on SSH",
    resource: "sg-12345",
    domain: "network",
    compliance: {
      cis_aws: ["5.2"],
      nist_800_53: ["SC-7"],
      pci_dss: ["1.2.1"],
      hipaa: [],
      soc2: ["CC6.6"],
    },
    remediation_id: "REM_ec2_05",
  },
];

export const mockDriftAlerts: DriftAlertsResponse = {
  alerts: [
    {
      type: "new_violation",
      check_id: "s3_block_public_acls",
      resource: "arn:aws:s3:::test",
      severity: "critical",
      risk_score: 92,
      timestamp: new Date().toISOString(),
      trigger_event: "PutBucketPublicAccessBlock",
      reason: "Public access enabled",
      domain: "data_protection",
      previous_status: "ok",
      current_status: "alarm",
    },
  ],
};

export const mockRiskSummary: RiskSummary = {
  total_scored: 10,
  by_category: {
    critical: 2,
    high: 3,
    medium: 3,
    low: 2,
  },
  by_domain: {
    data_protection: 4,
    network: 3,
    identity_access: 3,
  },
  highest_risk: [
    {
      resource_arn: "arn:aws:s3:::public-bucket",
      check_id: "s3_block_public_acls",
      risk_score: 92,
      severity: "critical",
      domain: "data_protection",
    },
  ],
};

export const mockRiskScores: RiskScoresResponse = {
  scores: [
    {
      resource_arn: "arn:aws:s3:::public-bucket",
      check_id: "s3_block_public_acls",
      risk_score: 92,
      category: "critical",
      severity: "critical",
      domain: "data_protection",
      last_evaluated: new Date().toISOString(),
    },
  ],
};

export const handlers = [
  // Health
  http.get(`${BASE}/health`, () =>
    HttpResponse.json(mockHealth),
  ),

  // Compliance
  http.get(`${BASE}/v1/compliance/score`, () =>
    HttpResponse.json(mockCompliance),
  ),

  // Violations
  http.get(`${BASE}/v1/violations`, () =>
    HttpResponse.json(mockViolations),
  ),

  // Drift Alerts
  http.get(`${BASE}/v1/drift/alerts`, () =>
    HttpResponse.json(mockDriftAlerts),
  ),

  // Risk
  http.get(`${BASE}/v1/risk/summary`, () =>
    HttpResponse.json(mockRiskSummary),
  ),
  http.get(`${BASE}/v1/risk/scores`, () =>
    HttpResponse.json(mockRiskScores),
  ),

  // Scans
  http.post(`${BASE}/v1/scans`, () =>
    HttpResponse.json({
      account_id: "123456789012",
      region: "us-east-1",
      collection_timestamp: new Date().toISOString(),
      collection_mode: "full",
    }),
  ),
];
