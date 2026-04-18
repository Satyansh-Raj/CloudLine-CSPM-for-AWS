"""Tests for OPA CLI client."""

import json
from unittest.mock import MagicMock, patch

from app.engine.opa_cli import OPACLIClient


class TestOPACLIClient:
    def setup_method(self):
        self.client = OPACLIClient(
            opa_binary="/usr/local/bin/opa",
            policy_dir="/tmp/policies",
        )

    @patch("app.engine.opa_cli.subprocess.run")
    def test_evaluate_success(self, mock_run):
        """Test successful OPA evaluation."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({
                "result": [{
                    "expressions": [{
                        "value": [
                            {
                                "check_id": "C01",
                                "status": "alarm",
                            }
                        ]
                    }]
                }]
            }),
            stderr="",
        )
        results = self.client.evaluate(
            {"test": True},
            "data.aws.identity.iam.violations",
        )
        assert len(results) == 1
        assert results[0]["check_id"] == "C01"

    @patch("app.engine.opa_cli.subprocess.run")
    def test_evaluate_nonzero_return(self, mock_run):
        """Test OPA returning non-zero exit code."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="error: policy parse",
        )
        results = self.client.evaluate(
            {}, "data.aws.test"
        )
        assert results == []

    @patch("app.engine.opa_cli.subprocess.run")
    def test_evaluate_timeout(self, mock_run):
        """Test OPA evaluation timing out."""
        import subprocess

        mock_run.side_effect = (
            subprocess.TimeoutExpired("opa", 30)
        )
        results = self.client.evaluate(
            {}, "data.aws.test"
        )
        assert results == []

    @patch("app.engine.opa_cli.subprocess.run")
    def test_evaluate_exception(self, mock_run):
        """Test unexpected exception during eval."""
        mock_run.side_effect = OSError("no binary")
        results = self.client.evaluate(
            {}, "data.aws.test"
        )
        assert results == []

    @patch("app.engine.opa_cli.subprocess.run")
    def test_evaluate_all_success(self, mock_run):
        """Test evaluate_all returns keyed results."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({
                "result": [{
                    "expressions": [{
                        "value": {
                            "iam_root_account": {
                                "violations": [{
                                    "check_id": "C01",
                                    "status": "alarm",
                                }],
                                "compliant": [],
                            }
                        }
                    }]
                }]
            }),
            stderr="",
        )
        results = self.client.evaluate_all(
            {"test": True}
        )
        assert "iam_root_account" in results
        v = results["iam_root_account"]["violations"]
        assert len(v) == 1

    @patch("app.engine.opa_cli.subprocess.run")
    def test_evaluate_all_nonzero(self, mock_run):
        """Test evaluate_all with failure."""
        mock_run.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="error",
        )
        results = self.client.evaluate_all({})
        assert results == {}

    @patch("app.engine.opa_cli.subprocess.run")
    def test_evaluate_all_exception(self, mock_run):
        """Test evaluate_all with exception."""
        mock_run.side_effect = OSError("no binary")
        results = self.client.evaluate_all({})
        assert results == {}

    def test_parse_output_valid(self):
        """Test parsing valid OPA JSON output."""
        stdout = json.dumps({
            "result": [{
                "expressions": [{
                    "value": [{"check_id": "C01"}]
                }]
            }]
        })
        result = self.client._parse_output(stdout)
        assert len(result) == 1

    def test_parse_output_dict_value(self):
        """Test parsing when value is a single dict."""
        stdout = json.dumps({
            "result": [{
                "expressions": [{
                    "value": {"not": "a list"}
                }]
            }]
        })
        result = self.client._parse_output(stdout)
        assert result == [{"not": "a list"}]

    def test_parse_output_invalid_json(self):
        """Test parsing invalid JSON."""
        result = self.client._parse_output(
            "not json"
        )
        assert result == []

    def test_parse_output_empty(self):
        """Test parsing empty result."""
        stdout = json.dumps({"result": [{}]})
        result = self.client._parse_output(stdout)
        assert result == []

    @patch("app.engine.opa_cli.subprocess.run")
    def test_evaluate_all_skips_non_dict(
        self, mock_run
    ):
        """Test evaluate_all skips non-dict values."""
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({
                "result": [{
                    "expressions": [{
                        "value": {
                            "risk_scoring": {
                                "severity_weights": {
                                    "critical": 100
                                }
                            },
                            "iam_root_mfa": {
                                "violations": [{
                                    "check_id": "C01",
                                    "status": "alarm",
                                }],
                            },
                        }
                    }]
                }]
            }),
            stderr="",
        )
        results = self.client.evaluate_all({})
        assert "iam_root_mfa" in results
