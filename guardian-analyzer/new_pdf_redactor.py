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

    def encrypt_pdf(
        self,
        input_path: str,
        output_path: str,
        password: str,
        owner_password: str = None,  # Optional different password for owner
    ) -> Dict[str, Any]:
        """Encrypt PDF with password protection"""
        try:
            # Open the PDF
            doc = fitz.open(input_path)
            
            # Define permissions bit field
            permissions = (
                fitz.PDF_PERM_ACCESSIBILITY  # always use this
                | fitz.PDF_PERM_PRINT       # permit printing
                | fitz.PDF_PERM_COPY        # permit copying
                | fitz.PDF_PERM_ANNOTATE    # permit annotations
            )

            # Save with encryption
            doc.save(
                output_path,
                owner_pw=owner_password if owner_password else password,  # owner password
                user_pw=password,                                        # user password
                encryption=fitz.PDF_ENCRYPT_AES_256,                     # encryption method
                permissions=permissions,                                 # user permissions
                garbage=3,                                              # garbage collection
                deflate=True                                            # compress contents
            )
            
            doc.close()
            
            return {
                "status": "success",
                "message": "PDF encrypted successfully",
                "output_path": output_path
            }

        except Exception as e:
            logger.error(f"Error encrypting PDF: {str(e)}")
            raise Exception(f"Error encrypting PDF: {str(e)}")

    def redact_pdf(
        self,
        pdf_path: str,
        output_path: str,
        language: str = "en",
        additional_keywords: List[str] = None,
        custom_regex: List[str] = None,
        entities: List[str] = None,
        redaction_style: str = "blackbox",
    ) -> Dict[str, Any]:
        """
        Analyze and redact PDF using Guardian analysis with comprehensive redaction
        """
        try:
            doc = fitz.open(pdf_path)
            detected_entities = {}

            # First pass: Entity Detection
            for page_num in range(len(doc)):
                page = doc[page_num]
                page_text = page.get_text()

                # Analyze text with Guardian
                analyzer_results = self.analyzer.analyze(
                    text=page_text, language=language, entities=entities
                )

                # Store entities with their types
                for result in analyzer_results:
                    entity_text = page_text[result.start : result.end]
                    if len(entity_text.strip()) > 2:
                        detected_entities[entity_text] = result.entity_type

            # Prepare redaction configuration
            redaction_config = {
                "keywords": list(detected_entities.keys()),
                "regex_patterns": self.default_regex_patterns.copy(),
            }

            # Add additional keywords and patterns
            if additional_keywords:
                redaction_config["keywords"].extend(additional_keywords)
            if custom_regex:
                redaction_config["regex_patterns"].extend(custom_regex)

            # Perform Redaction
            for page_num in range(len(doc)):
                page = doc[page_num]
                page_text = page.get_text()

                # Get all targets including regex matches
                redact_targets = redaction_config["keywords"] + [
                    re.findall(pattern, page_text)[0]
                    for pattern in redaction_config["regex_patterns"]
                    if re.findall(pattern, page_text)
                ]

                # Sort targets by length (longest first) to avoid partial matches
                redact_targets = sorted(redact_targets, key=len, reverse=True)

                for target in redact_targets:
                    try:
                        instances = self.find_text_instances(page, target)

                        for rect in instances:
                            if redaction_style == "blackbox":
                                # Traditional black box redaction
                                page.add_redact_annot(rect)
                                page.draw_rect(rect, color=(0, 0, 0), fill=(0, 0, 0))
                            else:  # label style
                                # Get entity type (default to "CUSTOM" for additional keywords)
                                entity_type = detected_entities.get(target, "CUSTOM")

                                # White out original text
                                page.draw_rect(rect, color=(1, 1, 1), fill=(1, 1, 1))

                                # Calculate center position for text
                                label = f"[{entity_type}]"
                                font_size = 8  # Adjust this value if needed

                                # Calculate text position to center it in the rectangle
                                text_width = (
                                    len(label) * font_size * 0.5
                                )  # Approximate width
                                text_height = font_size

                                x = rect.x0 + (rect.width - text_width) / 2
                                y = (
                                    rect.y0
                                    + (rect.height - text_height) / 2
                                    + text_height * 0.5
                                )

                                # Insert centered label
                                page.insert_text(
                                    point=(x, y),
                                    text=label,
                                    fontsize=font_size,
                                    color=(0, 0, 0),
                                    render_mode=0,  # Normal text rendering
                                )
                    except Exception as e:
                        logger.error(f"Error processing '{target}': {e}")

                if redaction_style == "blackbox":
                    page.apply_redactions()

            # Save the processed document
            doc.save(output_path)
            doc.close()

            return {
                "status": "success",
                "detected_entities": detected_entities,
                "output_path": output_path,
                "redaction_style": redaction_style,
            }

        except Exception as e:
            logger.error(f"Error redacting PDF: {e}")
            raise

    def redact_strings_only(
        self,
        pdf_path: str,
        output_path: str,
        strings_to_redact: List[str],
        redaction_style: str = "blackbox",
    ) -> Dict[str, Any]:
        """
        Redact only specific strings from PDF without any analysis
        """
        try:
            doc = fitz.open(pdf_path)
            
            # Sort strings by length (longest first) to avoid partial matches
            redact_targets = sorted(strings_to_redact, key=len, reverse=True)

            # Perform Redaction
            for page_num in range(len(doc)):
                page = doc[page_num]
                
                for target in redact_targets:
                    try:
                        instances = self.find_text_instances(page, target)

                        for rect in instances:
                            if redaction_style == "blackbox":
                                # Traditional black box redaction
                                page.add_redact_annot(rect)
                                page.draw_rect(rect, color=(0, 0, 0), fill=(0, 0, 0))
                            else:  # label style
                                # White out original text
                                page.draw_rect(rect, color=(1, 1, 1), fill=(1, 1, 1))
                                
                                # Add label
                                label = "[REDACTED]"
                                font_size = 8
                                
                                # Calculate text position
                                text_width = len(label) * font_size * 0.5
                                text_height = font_size
                                
                                x = rect.x0 + (rect.width - text_width) / 2
                                y = rect.y0 + (rect.height - text_height) / 2 + text_height * 0.5
                                
                                # Insert centered label
                                page.insert_text(
                                    point=(x, y),
                                    text=label,
                                    fontsize=font_size,
                                    color=(0, 0, 0),
                                    render_mode=0,
                                )
                    except Exception as e:
                        logger.error(f"Error processing '{target}': {e}")

                if redaction_style == "blackbox":
                    page.apply_redactions()

            # Save the processed document
            doc.save(output_path)
            doc.close()

            return {
                "status": "success",
                "redacted_strings": strings_to_redact,
                "output_path": output_path,
                "redaction_style": redaction_style,
            }

        except Exception as e:
            logger.error(f"Error redacting strings from PDF: {e}")
            raise
