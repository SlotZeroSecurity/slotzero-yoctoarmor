"""Presentation checks with inert ledgers; lifecycle tests cover approval gates."""

from support import reference_relative
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from report_assembly import BODY_SECTIONS, assemble, markdown_sections, validate_assembled

ROOT = Path(__file__).resolve().parents[1]


class AnnexLayoutTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.run = Path(temp.name)
        self.manifest = {"target": "synthetic-target", "target_revision": "fixture",
                         "scope": ["src/lib.rs"], "discovery_passes_planned": 1}
        self.state = {"discovery_pass_status": {"l2": {"1": "complete"}, "l3": {"1": "complete"}}}
        (self.run / "run-state.json").write_text(json.dumps(self.state))
        self.banner = (ROOT / reference_relative('technical_annex_template')).read_text().split("\n# ", 1)[0]
        self.rows = []
        self.write_rows("work-packets.jsonl", [])
        self.write_rows("dispositions.jsonl", [])
        self.population(0)

    def write_rows(self, name, rows):
        (self.run / name).write_text("".join(json.dumps(row) + "\n" for row in rows))

    def population(self, count):
        self.rows = [{"candidate_id": f"F-{i}", "verdict": "valid", "severity": "high",
                      "confidence": {"total": 11}} for i in range(count)]
        self.rows.append({"candidate_id": "LEAD", "verdict": "lead", "severity": None,
                          "confidence": {"total": 0}})
        self.write_rows("verdicts.jsonl", self.rows)
        self.write_rows("deduplicated.jsonl", [{"candidate_id": row["candidate_id"],
                        "attacker": "a fixture user", "root_cause": "synthetic condition",
                        "terminal_harm": "synthetic harm"} for row in self.rows])

    def body(self):
        contents = {name: "Synthetic fixture content." for name in BODY_SECTIONS}
        contents["Findings"] = "\n\n".join(
            f"### {row['candidate_id']}\n\nConfidence: 11/13\n\n#### Recommendation\n\nFixture fix."
            for row in self.rows if row["verdict"] == "valid") or "No verified findings."
        contents["Unverified leads"] = "LEAD: unverified; missing receiver implementation blocks validation."
        contents["Testing and limitations"] = "Execution blocked by the missing receiver; no successful test is claimed."
        return self.banner + "\n# 🔐 NEAR YoctoArmor v1 Security Review — fixture\n\n" + "\n\n".join(
            f"## {name}\n\n{contents[name]}" for name in BODY_SECTIONS) + "\n"

    def test_zero_and_multiple_findings_with_unscored_blocked_lead(self):
        for count in (0, 4):
            for stage in ("draft", "approved"):
                with self.subTest(count=count, stage=stage):
                    self.population(count)
                    text = assemble(self.run, self.manifest, self.body(), stage=stage)
                    validate_assembled(self.run, self.manifest, text, stage=stage)
                    self.assertIn(f"## Top findings — top {min(3, count)} of {count}", text)
                    self.assertIn(f"**Review stage:** {stage.title()}", text)
                    self.assertNotIn("LEAD", text.split("## Architecture", 1)[0])
                    self.assertIn("Execution blocked", text)
                    self.assertNotIn("## Threat-model exclusions", text)
                    self.assertEqual([name for name, _ in markdown_sections(text)][2:], list(BODY_SECTIONS))
                    self.state["report"] = {"stage": stage}
                    (self.run / "run-state.json").write_text(json.dumps(self.state))
                    validate_assembled(self.run, self.manifest, text)

    def test_section_order_removals_and_stage_cannot_be_forged(self):
        good = assemble(self.run, self.manifest, self.body())
        invalid = [
            good.replace("## Testing and limitations", "## Audit metadata"),
            good + "\n## Raw candidate disposition appendix\nPrivate bookkeeping\n",
            good.replace("## Findings index", "## Unverified leads"),
            good.replace("Draft — pending human review.", "Approved — human review recorded."),
            good.replace("NEAR YoctoArmor v1  - SLOT ZERO SECURITY", "NEAR MULTI-AGENT SECURITY SCANNER"),
        ]
        for text in invalid:
            with self.subTest(text=text[-80:]), self.assertRaises(ValueError):
                validate_assembled(self.run, self.manifest, text, stage="draft")

    def test_pending_review_and_code_headings(self):
        body = self.body() + "\n## Pending review\nA fixture decision is unresolved.\n"
        draft = assemble(self.run, self.manifest, body)
        validate_assembled(self.run, self.manifest, draft, stage="draft")
        approved = assemble(self.run, self.manifest, body, stage="approved")
        with self.assertRaisesRegex(ValueError, "cannot contain pending review"):
            validate_assembled(self.run, self.manifest, approved, stage="approved")
        body = self.body().replace("## Unverified leads", "```text\n## Audit metadata\n```\n\n## Unverified leads")
        validate_assembled(self.run, self.manifest, assemble(self.run, self.manifest, body), stage="draft")

    def test_finding_evidence_cannot_be_moved_to_another_section(self):
        self.population(2)
        text = assemble(self.run, self.manifest, self.body())
        validate_assembled(self.run, self.manifest, text, stage="draft")
        start = text.index("### F-1")
        end = text.index("## Unverified leads")
        detail = text[start:end]
        moved = text[:start] + text[end:] + "\n" + detail
        with self.assertRaisesRegex(ValueError, "absent from detailed report"):
            validate_assembled(self.run, self.manifest, moved, stage="draft")
        with self.assertRaisesRegex(ValueError, "requires a complete fix"):
            validate_assembled(self.run, self.manifest, text.replace("#### Recommendation", "#### Note", 1), stage="draft")


if __name__ == "__main__":
    unittest.main()
