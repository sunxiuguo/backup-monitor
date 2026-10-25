"""Standard-library negative controls for validation gates; no HA or build execution."""
import tempfile
import unittest
from pathlib import Path
import xml.etree.ElementTree as ET

import run_native as validator


def red():
    case = ET.Element("testcase", classname="tests.test_duplicati_result_workflow", name="test_result_workflow[old_fatal_then_success]")
    failure = ET.SubElement(case, "failure", message="assert 'error' == 'success'")
    failure.text = 'assert job["last_result"] == expected'
    return case


class Gates(unittest.TestCase):
    def test_exact_red_accepted(self):
        validator.check_red([red()])

    def test_wrong_node_rejected(self):
        case = red()
        case.set("name", "unrelated")
        with self.assertRaises(ValueError):
            validator.check_red([case])

    def test_wrong_assertion_rejected(self):
        case = red()
        case.find("failure").set("message", "TypeError: wrong signature")
        with self.assertRaises(ValueError):
            validator.check_red([case])

    def test_setup_error_rejected(self):
        case = red()
        case.remove(case.find("failure"))
        ET.SubElement(case, "error", message="ImportError")
        with self.assertRaises(ValueError):
            validator.check_red([case])

    def test_red_skip_rejected(self):
        case = red()
        ET.SubElement(case, "skipped")
        with self.assertRaises(ValueError):
            validator.check_red([case])

    def test_green_skip_rejected(self):
        case = ET.Element("testcase")
        ET.SubElement(case, "skipped")
        with self.assertRaises(ValueError):
            validator.check_green([case], 1)

    def test_changed_source_rejected(self):
        previous = dict(validator.TRACKED)
        try:
            with tempfile.TemporaryDirectory() as temp:
                file = Path(temp) / "synthetic.py"
                file.write_text("before")
                validator.TRACKED.clear()
                validator.track(file)
                file.write_text("after")
                with self.assertRaises(ValueError):
                    validator.verify_tracked()
        finally:
            validator.TRACKED.clear()
            validator.TRACKED.update(previous)

    def test_inherited_environment_injection_removed(self):
        import os
        from unittest.mock import patch
        with patch.dict(os.environ, {"PYTHONPATH": "/synthetic", "PYTHONHOME": "/synthetic", "PYTHONSTARTUP": "/synthetic", "PYTEST_PLUGINS": "unreviewed"}):
            env = validator.clean_environment()
        self.assertNotIn("PYTHONPATH", env)
        self.assertNotIn("PYTHONHOME", env)
        self.assertNotIn("PYTHONSTARTUP", env)
        self.assertNotIn("PYTEST_PLUGINS", env)
        self.assertEqual(env["PIP_NO_INDEX"], "1")
        self.assertEqual(env["PIP_CONFIG_FILE"], "/dev/null")


if __name__ == "__main__":
    unittest.main()
