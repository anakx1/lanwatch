"""Frontend behavior tests for the network topology map."""

from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path


class TopologyFrontendTests(unittest.TestCase):
    def test_topology_rendering_and_safety(self) -> None:
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node.js is not available for frontend tests")
        script = Path(__file__).with_name("topology.test.js")
        result = subprocess.run(
            [node, str(script)],
            cwd=script.parent.parent,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("ok testGatewayIsRenderedOnce", result.stdout)
        self.assertIn("ok testLargeNetworksAreCappedAndStable", result.stdout)
        self.assertIn("ok testUntrustedTextIsRenderedSafely", result.stdout)
        self.assertIn("ok testDeviceClickOpensExistingDrawer", result.stdout)
        self.assertIn(
            "ok testGatewaySelectionShowsNetworkDetailsWithoutDeviceDrawer",
            result.stdout,
        )
        self.assertIn(
            "ok testSearchAndFiltersUpdateHighlightingImmediately",
            result.stdout,
        )
        self.assertIn("ok testZoomPanAndFitLimits", result.stdout)
        self.assertIn("ok testKeyboardAndScreenReaderControls", result.stdout)
        self.assertIn("ok testVeryLargeNetworksStayBounded", result.stdout)
        self.assertIn("ok testTopologySkipsRedundantRenders", result.stdout)
        self.assertIn("ok testTopologyRendersPreserveKeyboardFocus", result.stdout)
        self.assertIn(
            "ok testTopologyNetworkChangeResetsTransientStateAndNodes",
            result.stdout,
        )
        self.assertIn(
            "ok testGatewaySelectionUsesSafeTextForUntrustedData",
            result.stdout,
        )
