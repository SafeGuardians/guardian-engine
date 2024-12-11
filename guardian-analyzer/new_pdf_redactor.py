import io
import re
import fitz
import logging
import concurrent.futures
import multiprocessing
import os
from typing import List, Dict, Any, Optional
from guardian_analyzer import AnalyzerEngine
from datetime import datetime

# Change logger name
logger = logging.getLogger("guardian-analyzer")

class GuardianPDFRedactor:
    def __init__(self, analyzer_engine: AnalyzerEngine = None):
        """
        PDF Redactor that uses Guardian analysis results with comprehensive redaction
        """
        self.analyzer = analyzer_engine or AnalyzerEngine()

        # Precompile common regex patterns for efficiency
        self.default_regex_patterns = [
            r"\b[A-Z]{2}\d{6}\b",  # Default ID-like pattern
            r"\b\d{3}-\d{2}-\d{4}\b",  # SSN pattern
            r"\b\d{16}\b",  # Credit card-like pattern
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",  # Email pattern
        ]

    def extract_entities_from_analysis(self, analyzer_results, text: str) -> List[str]:
        """Extract actual text strings from analyzer results"""
        entities = []
        for result in analyzer_results:
            entity_text = text[result.start : result.end]
            if len(entity_text.strip()) > 2:
                entities.append(entity_text)
        return list(set(entities))  # Remove duplicates

    def find_text_instances(self, page, text):
        """
        Find all text instances on a page and return their rectangles
        """
        instances = page.search_for(text)
        return instances

    def redact_pdf(
        self,
        pdf_path: str,
        output_path: str,
        language: str = "en",
        additional_keywords: List[str] = None,
        custom_regex: List[str] = None,
        entities: List[str] = None,
    ) -> Dict[str, Any]:
        """
        Analyze and redact PDF using Guardian analysis with comprehensive redaction
        """
        try:
            # Open document in update mode
            doc = fitz.open(pdf_path)
            detected_entities = set()

            # First pass: Entity Detection
            for page_num in range(len(doc)):
                page = doc[page_num]
                page_text = page.get_text()

                # Analyze text with Guardian
                analyzer_results = self.analyzer.analyze(
                    text=page_text, 
                    language=language,
                    entities=entities
                )
                print(f"Page {page_num + 1} - Detected entities: {analyzer_results}")

                # Extract entities from analysis
                page_entities = self.extract_entities_from_analysis(
                    analyzer_results, page_text
                )
                detected_entities.update(page_entities)

            # Prepare redaction configuration
            redaction_config = {
                "keywords": list(detected_entities),
                "regex_patterns": [],
            }

            # Validate and add regex patterns
            for pattern in self.default_regex_patterns:
                try:
                    re.compile(pattern)  # Test if pattern is valid
                    redaction_config["regex_patterns"].append(pattern)
                except re.error:
                    logger.warning(f"Invalid regex pattern skipped: {pattern}")

            # Add additional keywords and patterns
            if additional_keywords:
                redaction_config["keywords"].extend(additional_keywords)
            if custom_regex:
                for pattern in custom_regex:
                    try:
                        re.compile(pattern)  # Test if pattern is valid
                        redaction_config["regex_patterns"].append(pattern)
                    except re.error:
                        logger.warning(f"Invalid custom regex pattern skipped: {pattern}")

            # Perform Redaction
            for page_num in range(len(doc)):
                page = doc[page_num]
                page_text = page.get_text()

                # First redact keywords
                for keyword in redaction_config["keywords"]:
                    try:
                        instances = self.find_text_instances(page, keyword)
                        for rect in instances:
                            page.add_redact_annot(rect)
                            page.draw_rect(rect, color=(0, 0, 0), fill=(0, 0, 0))
                    except Exception as e:
                        logger.warning(f"Error redacting keyword '{keyword}': {e}")

                # Then handle regex patterns
                for pattern in redaction_config["regex_patterns"]:
                    try:
                        matches = re.finditer(pattern, page_text)
                        for match in matches:
                            target = match.group()
                            instances = self.find_text_instances(page, target)
                            for rect in instances:
                                page.add_redact_annot(rect)
                                page.draw_rect(rect, color=(0, 0, 0), fill=(0, 0, 0))
                    except Exception as e:
                        logger.warning(f"Error processing regex pattern '{pattern}': {e}")

                # Apply redactions for this page
                page.apply_redactions()

            # Save the redacted document
            doc.save(output_path)
            doc.close()

            return {
                "status": "success",
                "detected_entities": list(detected_entities),
                "output_path": output_path,
            }

        except Exception as e:
            logger.error(f"Error redacting PDF: {e}")
            raise