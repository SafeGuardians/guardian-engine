from typing import List, Optional, Tuple
import re

from guardian_analyzer import Pattern, PatternRecognizer
from guardian_analyzer.analyzer_utils import PresidioAnalyzerUtils as Utils


class InAadhaarRecognizer(PatternRecognizer):
    """
    Recognizes Indian UIDAI Person Identification Number ("AADHAAR").

    Reference: https://en.wikipedia.org/wiki/Aadhaar
    A 12 digit unique number that is issued to each individual by Government of India
    :param patterns: List of patterns to be used by this recognizer
    :param context: List of context words to increase confidence in detection
    :param supported_language: Language this recognizer supports
    :param supported_entity: The entity this recognizer can detect
    :param replacement_pairs: List of tuples with potential replacement values
    for different strings to be used during pattern matching.
    This can allow a greater variety in input, for example by removing dashes or spaces.
    """


    PATTERNS = [
        Pattern(
            "AADHAAR (Strong)",
            r"\b[2-9][0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b",  # Matches format: XXXX XXXX XXXX
            0.75,  # Increased confidence score
        ),
        Pattern(
            "AADHAAR (Medium)",
            r"\b[2-9][0-9]{11}\b",  # Matches 12 digits starting with 2-9
            0.6,
        ),
        Pattern(
            "AADHAAR Header",
            r"(?i)(आधार|aadhaar|आधार\s*-|aadhaar\s*-)",  # Add Hindi support
            0.3,
        )
    ]

    CONTEXT = [
        "aadhaar",
        "uidai",
        "आधार",  # Hindi
        "आम आदमी का अधिकार",  # Common Hindi text on Aadhaar
        "government of india",
        "भारत सरकार",  # Hindi
        "unique identification",
        "identification number",
    ]

    utils = None

    def __init__(
        self,
        patterns: Optional[List[Pattern]] = None,
        context: Optional[List[str]] = None,
        supported_language: str = "en",
        supported_entity: str = "IN_AADHAAR",
        replacement_pairs: Optional[List[Tuple[str, str]]] = None,
    ):
        self.replacement_pairs = (
            replacement_pairs
            if replacement_pairs
            else [("-", ""), (" ", ""), (":", "")]
        )
        patterns = patterns if patterns else self.PATTERNS
        context = context if context else self.CONTEXT
        super().__init__(
            supported_entity=supported_entity,
            patterns=patterns,
            context=context,
            supported_language=supported_language,
        )

    def validate_result(self, pattern_text: str) -> bool:
        """Validate Aadhaar number with enhanced checks."""
        sanitized_value = Utils.sanitize_value(pattern_text, self.replacement_pairs)
        
        # Basic format check
        if not sanitized_value.isdigit() or len(sanitized_value) != 12:
            return False
        
        # First digit check (must be 2-9)
        if not 2 <= int(sanitized_value[0]) <= 9:
            return False
        
        # Check for sequential numbers
        if any(str(i) * 4 in sanitized_value for i in range(10)):
            return False
        
        # Verhoeff algorithm check
        if not Utils.is_verhoeff_number(int(sanitized_value)):
            return False
        
        # Check surrounding context
        return True

    def __check_aadhaar(self, sanitized_value: str) -> bool:
        is_valid_aadhaar: bool = False
        if (
            len(sanitized_value) == 12
            and sanitized_value.isnumeric() is True
            and int(sanitized_value[0]) >= 2
            and Utils.is_verhoeff_number(int(sanitized_value)) is True
            and Utils.is_palindrome(sanitized_value) is False
        ):
            is_valid_aadhaar = True
        return is_valid_aadhaar

    def enhance_context_scoring(self, text: str, start: int, end: int, score: float) -> float:
        """Enhance scoring based on surrounding context."""
        
        # Check for Aadhaar card visual indicators
        context_indicators = {
            r"(?i)government of india": 0.3,
            r"(?i)भारत सरकार": 0.3,
            r"(?i)aadhaar": 0.4,
            r"(?i)आधार": 0.4,
            r"[0-9]{4}\s[0-9]{4}\s[0-9]{4}": 0.5,  # Properly formatted number
            r"qr\s*code": 0.2,  # QR code presence
        }
        
        context_window = text[max(0, start-50):min(len(text), end+50)]
        
        for pattern, weight in context_indicators.items():
            if re.search(pattern, context_window, re.IGNORECASE):
                score = min(0.99, score + weight)
        
        return score

    def normalize_aadhaar(self, text: str) -> str:
        """Normalize Aadhaar number format."""
        # Remove common OCR errors
        ocr_fixes = {
            'O': '0',
            'I': '1',
            'l': '1',
            'S': '5',
            'B': '8',
        }
        
        for wrong, correct in ocr_fixes.items():
            text = text.replace(wrong, correct)
        
        # Remove all non-digit characters
        text = ''.join(c for c in text if c.isdigit())
        
        return text
