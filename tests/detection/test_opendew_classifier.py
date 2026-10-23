"""Tests for OpenDEW signal classifier integration."""

import unittest
from c_uas.detection.opendew_classifier import (
    OpenDEWSignalClassifier,
    get_opendew_classifier,
    OPENDEW_PATH,
)


class TestOpenDEWClassifier(unittest.TestCase):
    def test_classifier_instantiates(self):
        clf = OpenDEWSignalClassifier()
        self.assertIsInstance(clf, OpenDEWSignalClassifier)

    def test_class_names(self):
        self.assertEqual(len(OpenDEWSignalClassifier.CLASS_NAMES), 12)
        self.assertIn("DJI_OcuSync", OpenDEWSignalClassifier.CLASS_NAMES)
        self.assertIn("ExpressLRS", OpenDEWSignalClassifier.CLASS_NAMES)
        self.assertIn("noise", OpenDEWSignalClassifier.CLASS_NAMES)

    def test_classify_iq_empty(self):
        clf = OpenDEWSignalClassifier()
        result = clf.classify_iq([])
        self.assertIn("predicted_class", result)
        self.assertIn("confidence", result)
        self.assertIn("method", result)
        self.assertIn("available", result)
        self.assertIn("probabilities", result)

    def test_classify_iq_fallback_when_unavailable(self):
        clf = OpenDEWSignalClassifier()
        # Force unavailable to test fallback
        clf._available = False
        clf._model = None
        result = clf.classify_iq([0.1, 0.2, 0.3, 0.4])
        self.assertEqual(result["predicted_class"], "unknown")
        self.assertEqual(result["confidence"], 0.0)
        self.assertFalse(result["available"])

    def test_singleton(self):
        c1 = get_opendew_classifier()
        c2 = get_opendew_classifier()
        self.assertIs(c1, c2)

    def test_opendew_path_exists(self):
        # The OpenDEW project path should exist on this system
        import os
        self.assertTrue(os.path.exists(OPENDEW_PATH))
