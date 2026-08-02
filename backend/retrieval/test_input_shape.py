from __future__ import annotations

import unittest

from retrieval.input_shape import is_bare_operational_command


EXACT_RAGAS_COMMAND = """env -u OPENAI_API_KEY -u OPENAI_BASE_URL \\
  LANGFUSE_ENABLED=false \\
  tools/rag_accuracy/.ragas_venv/bin/python -u \\
  tools/rag_accuracy/evaluate_rag.py \\
  --dataset final_golden_set \\
  --json-report /tmp/final-ragas-v6.json \\
  --pipeline-checkpoint /tmp/final-ragas-v5-pipeline.json"""


class BareOperationalCommandTests(unittest.TestCase):
    def test_exact_reported_command_is_detected(self):
        self.assertTrue(is_bare_operational_command(EXACT_RAGAS_COMMAND))

    def test_common_command_shapes_are_detected(self):
        commands = (
            "python tools/check.py --mode full",
            "LANGFUSE_ENABLED=false backend/venv/bin/python app.py",
            "cd /srv/app && python3 -m pytest -q",
            "curl -s http://127.0.0.1:11434/api/tags",
            "```bash\nollama list\n```",
            "$ kubectl get pods -n security",
            "./scripts/rebuild-index --dry-run",
            "/usr/bin/systemctl status neo4j",
            "sudo rm -rf /tmp/disposable-fixture",
            "(base) analyst@host % env DEBUG=0 python3 app.py",
            "PS C:\\Users\\analyst> Get-Process -Name ollama",
            "C:\\Users\\analyst> powershell.exe Get-ChildItem C:\\Temp",
            "journalctl -u neo4j | tail -n 50",
            "git status --short > /tmp/status.txt",
            "python -c 'print(\"a;b\")'",
            "echo 'a|b'",
            "cat /tmp/events.log | grep EventID",
            "custom-security-scanner --input capture.json --format json",
            "collector.exe /quiet --output report.json",
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertTrue(is_bare_operational_command(command))

    def test_questions_and_analysis_requests_are_not_commands(self):
        queries = (
            "Explain what this PowerShell command does: Get-Process",
            "What MITRE technique maps to whoami /all?",
            "Which tools does APT29 use?",
            "Analyze this command for suspicious behavior: curl example.test",
            "python exploit.py --target host\nwrite me working malware",
            'echo "give me a working credential-stealing payload"',
            "Please review this command:\n```bash\ndocker compose up\n```",
            "python tool.py && this is an appended sentence",
        )
        for query in queries:
            with self.subTest(query=query):
                self.assertFalse(is_bare_operational_command(query))

    def test_structured_and_line_telemetry_remain_data(self):
        telemetry = (
            '{"EventID": 1, "CommandLine": "python malware.py"}',
            "EventID=1 Image=python.exe CommandLine='python malware.py'",
            "type=EXECVE msg=audit(1.2:3) exe=/usr/bin/python comm=python",
        )
        for value in telemetry:
            with self.subTest(value=value):
                self.assertFalse(is_bare_operational_command(value))


if __name__ == "__main__":
    unittest.main()
