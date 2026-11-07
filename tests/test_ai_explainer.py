"""Offline tests for the optional Claude explanations. No API key or network needed."""
import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import ai_explainer  # noqa: E402

SAMPLE = pd.read_excel(ROOT / "sample-data/firewall-synthetic-validation.xlsx", sheet_name="firewall", header=1)


class FakeClient:
    """Records the request and answers with a valid explanation per finding."""

    def __init__(self, reply=None):
        self.calls = []
        self.reply = reply
        self.messages = SimpleNamespace(create=self._create)

    def _create(self, **kwargs):
        self.calls.append(kwargs)
        if self.reply is None:
            sent = json.loads(kwargs["messages"][0]["content"].split("\n", 1)[1])
            text = json.dumps([
                {"id": f["id"], "manager_summary": f"Summary for {f['rule'].get('Rule Name')}",
                 "engineer_note": "Check the rule.", "verify_before_change": "Confirm traffic."}
                for f in sent])
        else:
            text = self.reply
        return SimpleNamespace(content=[SimpleNamespace(type="text", text=text)])


def findings():
    profile = SAMPLE[SAMPLE["Rule Name"].isin(["missing-none", "uppercase"])]
    forwarding = SAMPLE[SAMPLE["Rule Name"].eq("forwarding-none-local-log-on")]
    return {"missing_profile": profile, "missing_log_forwarding": forwarding}


class PayloadTests(unittest.TestCase):
    def test_only_allowed_fields_are_sent(self):
        payload, _ = ai_explainer.build_payload(findings())
        self.assertEqual(len(payload), 3)
        for item in payload:
            self.assertTrue(set(item["rule"]).issubset(ai_explainer.ALLOWED_FIELDS))
            self.assertNotIn("UUID", item["rule"])
        self.assertIn("UUID", SAMPLE.columns)  # proves the export had it and it was dropped

    def test_rule_names_and_addresses_redacted_by_default(self):
        payload, mapping = ai_explainer.build_payload(findings())
        sent = json.dumps(payload)
        for name in ["missing-none", "uppercase", "forwarding-none-local-log-on"]:
            self.assertNotIn(name, sent)
        self.assertEqual(set(mapping.values()) >= {"missing-none", "uppercase"}, True)
        frame = pd.DataFrame([{"Rule Name": "r", "Source Address": "10.1.1.0/24;any",
                               "Destination Address": "web-servers"}])
        payload, mapping = ai_explainer.build_payload({"broad_address": frame})
        rule = payload[0]["rule"]
        self.assertEqual(rule["Source Address"], "ADDR-1;any")
        self.assertEqual(rule["Destination Address"], "ADDR-2")
        self.assertNotIn("10.1.1.0", json.dumps(payload))

    def test_redaction_can_be_turned_off(self):
        payload, mapping = ai_explainer.build_payload(findings(), redact=False)
        self.assertIn("missing-none", json.dumps(payload))
        self.assertEqual(mapping, {})

    def test_scope_statement_travels_with_each_finding(self):
        payload, _ = ai_explainer.build_payload(findings())
        forwarding = [p for p in payload if p["finding_type"] == "missing_log_forwarding"][0]
        self.assertIn("does NOT mean session logging is disabled", forwarding["check_scope"])

    def test_finding_cap_and_unknown_types(self):
        many = pd.concat([SAMPLE] * 3)
        payload, _ = ai_explainer.build_payload({"missing_profile": many}, max_findings=5)
        self.assertEqual(len(payload), 5)
        with self.assertRaises(ai_explainer.ExplainerError):
            ai_explainer.build_payload({"made_up": SAMPLE})


class ExplainTests(unittest.TestCase):
    def test_explanations_restore_real_names_locally(self):
        payload, mapping = ai_explainer.build_payload(findings())
        client = FakeClient()
        results = ai_explainer.explain_findings(payload, mapping, client=client, model="test-model")
        self.assertEqual(len(results), 3)
        self.assertEqual(client.calls[0]["model"], "test-model")
        self.assertNotIn("missing-none", client.calls[0]["messages"][0]["content"])
        self.assertTrue(any("missing-none" in r["manager_summary"] for r in results))

    def test_default_model_and_env_override(self):
        payload, _ = ai_explainer.build_payload(findings())
        client = FakeClient()
        with patch.dict("os.environ", {}, clear=True):
            ai_explainer.explain_findings(payload, client=client)
        self.assertEqual(client.calls[-1]["model"], ai_explainer.DEFAULT_MODEL)
        with patch.dict("os.environ", {"ANTHROPIC_MODEL": "claude-haiku-5-5"}):
            ai_explainer.explain_findings(payload, client=client)
        self.assertEqual(client.calls[-1]["model"], "claude-haiku-5-5")

    def test_missing_key_gives_clear_error(self):
        payload, _ = ai_explainer.build_payload(findings())
        with patch.dict("os.environ", {}, clear=True), self.assertRaises(ai_explainer.ExplainerError) as ctx:
            ai_explainer.explain_findings(payload)
        self.assertIn("ANTHROPIC_API_KEY", str(ctx.exception))

    def test_bad_responses_are_rejected(self):
        payload, _ = ai_explainer.build_payload(findings())
        bad = ["No JSON here", "[not json]",
               json.dumps([{"id": "F1", "manager_summary": "x"}]),
               json.dumps([{"id": "F99", "manager_summary": "a", "engineer_note": "b", "verify_before_change": "c"}]),
               json.dumps([{"id": "F1", "manager_summary": "a", "engineer_note": "b", "verify_before_change": "c"}])]
        for reply in bad:
            with self.subTest(reply=reply[:30]), self.assertRaises(ai_explainer.ExplainerError):
                ai_explainer.explain_findings(payload, client=FakeClient(reply))

    def test_response_wrapped_in_prose_still_parses(self):
        payload, _ = ai_explainer.build_payload(findings())
        items = [{"id": p["id"], "manager_summary": "a", "engineer_note": "b", "verify_before_change": "c"} for p in payload]
        reply = "Here you go:\n```json\n" + json.dumps(items) + "\n```"
        self.assertEqual(len(ai_explainer.explain_findings(payload, client=FakeClient(reply))), 3)

    def test_empty_payload_makes_no_call(self):
        client = FakeClient()
        self.assertEqual(ai_explainer.explain_findings([], client=client), [])
        self.assertEqual(client.calls, [])


if __name__ == "__main__":
    unittest.main()
