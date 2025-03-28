from abc import ABC

from guardian_analyzer import EntityRecognizer


class LocalRecognizer(ABC, EntityRecognizer):
    """PII entity recognizer which runs on the same process as the AnalyzerEngine."""
