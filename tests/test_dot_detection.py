"""
Tests for PAN and Aadhaar detection with dots
=============================================
Covers dots between groups, at beginning, and at end of IDs.
"""

import pytest

from src.detection.detect import detect_sensitive


# ---------------------------------------------------------------------------
# Aadhaar detection with dots
# ---------------------------------------------------------------------------

class TestAadhaarDotDetection:
    def test_aadhaar_dots_between_groups(self):
        result = detect_sensitive("Aadhaar: 2345.6789.0123")
        assert "AADHAAR" in result["detections"]
        assert result["block"] is True
        assert result["severity"] == "high"

    def test_aadhaar_dot_at_end(self):
        result = detect_sensitive("My Aadhaar is 234567890123.")
        assert "AADHAAR" in result["detections"]

    def test_aadhaar_dot_at_beginning(self):
        result = detect_sensitive("Aadhaar: .234567890123")
        assert "AADHAAR" in result["detections"]

    def test_aadhaar_single_dot_between_first_second_group(self):
        result = detect_sensitive("UID: 2345.67890123")
        assert "AADHAAR" in result["detections"]

    def test_aadhaar_single_dot_between_second_third_group(self):
        result = detect_sensitive("UID: 23456789.0123")
        assert "AADHAAR" in result["detections"]

    def test_aadhaar_all_dots_format(self):
        result = detect_sensitive("Aadhaar: 4567.8901.2345")
        assert "AADHAAR" in result["detections"]

    def test_aadhaar_mixed_dots_dashes(self):
        result = detect_sensitive("Aadhaar: 2345-6789.0123")
        assert "AADHAAR" in result["detections"]

    def test_aadhaar_mixed_dots_spaces(self):
        result = detect_sensitive("Aadhaar: 2345.6789 0123")
        assert "AADHAAR" in result["detections"]

    def test_aadhaar_no_separator(self):
        result = detect_sensitive("My Aadhaar is 234567890123")
        assert "AADHAAR" in result["detections"]

    def test_aadhaar_dashes(self):
        result = detect_sensitive("Aadhaar: 4567-8901-2345")
        assert "AADHAAR" in result["detections"]

    def test_aadhaar_spaces(self):
        result = detect_sensitive("Aadhaar: 4567 8901 2345")
        assert "AADHAAR" in result["detections"]

    def test_aadhaar_invalid_first_digit_with_dots(self):
        result = detect_sensitive("Not Aadhaar: 1234.5678.9012")
        assert "AADHAAR" not in result["detections"]

    def test_aadhaar_repeating_digits_with_dots(self):
        result = detect_sensitive("Aadhaar: 4444.4444.4444")
        assert "AADHAAR" not in result["detections"]

    def test_aadhaar_dot_at_both_ends(self):
        result = detect_sensitive("Aadhaar: .234567890123.")
        assert "AADHAAR" in result["detections"]


# ---------------------------------------------------------------------------
# PAN detection with dots
# ---------------------------------------------------------------------------

class TestPANDotDetection:
    def test_pan_valid_no_dots(self):
        result = detect_sensitive("My PAN is ABCDE1234F")
        assert "PAN" in result["detections"]
        assert result["block"] is True
        assert result["severity"] == "high"

    def test_pan_dot_between_letters_and_digits(self):
        result = detect_sensitive("PAN: ABCDE.1234F")
        assert "PAN" in result["detections"]

    def test_pan_dot_between_digits_and_suffix(self):
        result = detect_sensitive("PAN: ABCDE1234.F")
        assert "PAN" in result["detections"]

    def test_pan_dots_between_all_parts(self):
        result = detect_sensitive("PAN: ABCDE.1234.F")
        assert "PAN" in result["detections"]

    def test_pan_dot_at_beginning(self):
        result = detect_sensitive("PAN: .ABCDE1234F")
        assert "PAN" in result["detections"]

    def test_pan_dot_at_end(self):
        result = detect_sensitive("PAN: ABCDE1234F.")
        assert "PAN" in result["detections"]

    def test_pan_dot_at_both_ends(self):
        result = detect_sensitive("PAN: .ABCDE1234F.")
        assert "PAN" in result["detections"]

    def test_pan_lowercase_with_dots(self):
        result = detect_sensitive("My pan is abcde.1234.f")
        assert "PAN" in result["detections"]

    def test_pan_in_sentence_with_dots(self):
        result = detect_sensitive("Please use PAN ABCDE.1234F for filing.")
        assert "PAN" in result["detections"]

    def test_pan_dot_prefix_only(self):
        result = detect_sensitive("PAN: .ABCDE1234F in documents")
        assert "PAN" in result["detections"]

    def test_pan_dot_suffix_only(self):
        result = detect_sensitive("PAN: ABCDE1234F. verify please")
        assert "PAN" in result["detections"]

    def test_pan_mixed_case_with_dots(self):
        result = detect_sensitive("PAN: AbCdE.1234.f")
        assert "PAN" in result["detections"]


# ---------------------------------------------------------------------------
# Edge cases: dots with other separators
# ---------------------------------------------------------------------------

class TestDotEdgeCases:
    def test_aadhaar_in_email_context(self):
        result = detect_sensitive("Send Aadhaar 2345.6789.0123 to admin")
        assert "AADHAAR" in result["detections"]

    def test_pan_in_code_context(self):
        result = detect_sensitive("pan = ABCDE.1234F")
        assert "PAN" in result["detections"]

    def test_aadhaar_in_json(self):
        result = detect_sensitive('{"aadhaar": "2345.6789.0123"}')
        assert "AADHAAR" in result["detections"]

    def test_pan_in_json(self):
        result = detect_sensitive('{"pan": "ABCDE.1234F"}')
        assert "PAN" in result["detections"]

    def test_multiple_aadhaar_with_dots(self):
        result = detect_sensitive("First: 2345.6789.0123 and second: 4567.8901.2345")
        assert "AADHAAR" in result["detections"]

    def test_pan_and_aadhaar_with_dots(self):
        result = detect_sensitive("PAN: ABCDE.1234F and Aadhaar: 2345.6789.0123")
        assert "PAN" in result["detections"]
        assert "AADHAAR" in result["detections"]
