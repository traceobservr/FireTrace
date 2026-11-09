"""
Automated unit tests for FireTrace.
Tests backend detection, prerequisite checking, command building, and TUI composition.
"""

import unittest
from backend import (
    DistroDetector,
    PrerequisiteChecker,
    CommandFactory,
    TOOL_REGISTRY,
)
from app import FireTraceApp


class TestBackend(unittest.TestCase):
    """Test backend engine components."""

    def test_distro_detection(self):
        distro = DistroDetector.detect()
        self.assertIsNotNone(distro.os_type)
        self.assertIsNotNone(distro.package_family)

    def test_prerequisite_checker(self):
        report = PrerequisiteChecker.run_check()
        self.assertGreaterEqual(len(report.statuses), 6)
        self.assertIn("nmap", [s.tool.binary for s in report.statuses])

    def test_command_factory_guards(self):
        # Target must be set
        with self.assertRaises(ValueError):
            CommandFactory.build("run nmap-quick", "Not Set")

        with self.assertRaises(ValueError):
            CommandFactory.build("run nmap-quick", "")

        # Dangerous characters blocked
        with self.assertRaises(ValueError):
            CommandFactory.build("run nmap-quick", "10.10.10.1; rm -rf /")

        with self.assertRaises(ValueError):
            CommandFactory.build("run nmap-quick", "10.10.10.1 | bash")

    def test_command_factory_vectors(self):
        vector, binary = CommandFactory.build("run nmap-quick", "192.168.1.100")
        self.assertEqual(binary, "nmap")
        self.assertIn("192.168.1.100", vector)
        self.assertIn("-sV", vector)

        vector_ferox, binary_ferox = CommandFactory.build("run feroxbuster", "192.168.1.100")
        self.assertEqual(binary_ferox, "feroxbuster")
        self.assertIn("http://192.168.1.100/", vector_ferox)


class TestAppComposition(unittest.IsolatedAsyncioTestCase):
    """Test Textual app headless composition."""

    async def test_app_blank_slate_init(self):
        app = FireTraceApp()
        async with app.run_test(size=(120, 40)) as pilot:
            self.assertEqual(app.target_ip, "Not Set")
            self.assertEqual(str(app.query_one("#brand-title").content), "FIRETRACE")
            self.assertEqual(str(app.query_one("#brand-version").content), "v0.1.0")


if __name__ == "__main__":
    unittest.main()
