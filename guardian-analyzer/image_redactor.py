import cv2
import numpy as np
from PIL import Image, ImageDraw
import pytesseract
from typing import List, Dict, Any, Tuple
from guardian_analyzer import AnalyzerEngine
import logging


class PresidioImageRedactor:
    def __init__(self, analyzer_engine: AnalyzerEngine = None):
        """
        Image Redactor that uses Guardian analysis results
        """
        self.analyzer = analyzer_engine or AnalyzerEngine()
        self.logger = logging.getLogger("guardian-analyzer")

        # Use the same regex patterns as PDF redactor for consistency
        self.default_regex_patterns = [
            r"\b[A-Z]{2}\d{6}\b",  # Default ID-like pattern
            r"\b\d{3}-\d{2}-\d{4}\b",  # SSN pattern
            r"\b\d{16}\b",  # Credit card-like pattern
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",  # Email pattern
        ]

    def extract_entities_from_analysis(
        self, analyzer_results, text: str
    ) -> List[Dict[str, Any]]:
        """Extract text and positions from analyzer results"""
        entities = []
        for result in analyzer_results:
            entity_text = text[result.start : result.end]
            if len(entity_text.strip()) > 2:
                entities.append(
                    {
                        "text": entity_text,
                        "start": result.start,
                        "end": result.end,
                        "type": result.entity_type,
                        "score": result.score,
                    }
                )
        return entities

    def preprocess_image(self, image: np.ndarray) -> np.ndarray:
        """Preprocess image for better OCR results"""
        # Convert to grayscale
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        # Apply thresholding
        thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]
        return thresh

    def redact_image(
        self,
        image_path: str,
        output_path: str,
        language: str = "en",
        entities: List[str] = None,
        color_fill: Tuple[int, int, int] = (0, 0, 0),
    ) -> Dict[str, Any]:
        """
        Analyze and redact image using Guardian analysis
        """
        try:
            # Read and preprocess image
            image = cv2.imread(image_path)
            if image is None:
                raise ValueError("Could not read image")

            # Preprocess for better OCR
            processed_image = self.preprocess_image(image)

            # Extract text using OCR
            text = pytesseract.image_to_string(processed_image)

            print(f"Extracted text: {text}")

            # Get word boxes from OCR
            boxes = pytesseract.image_to_data(
                processed_image, output_type=pytesseract.Output.DICT
            )

            # Analyze text with Presidio
            analyzer_results = self.analyzer.analyze(
                text=text, language=language, entities=entities
            )

            # self.logger.info(f"Detected entities: {analyzer_results}")
            for result in analyzer_results:
                print(
                    f"Detected entity: {result.entity_type} :- {text[result.start:result.end]} Score: {result.score}"
                )

            # Extract entities with positions
            detected_entities = self.extract_entities_from_analysis(
                analyzer_results, text
            )

            # Convert to PIL for drawing
            pil_image = Image.fromarray(cv2.cvtColor(image, cv2.COLOR_BGR2RGB))
            draw = ImageDraw.Draw(pil_image)

            # Redact detected entities
            for entity in detected_entities:
                entity_text = entity["text"]
                # Find word positions in OCR results
                words = boxes["text"]
                for i, word in enumerate(words):
                    if entity_text in word:
                        # print(f"Redacting entity: {entity_text}", sep="\t")
                        x = boxes["left"][i]
                        y = boxes["top"][i]
                        w = boxes["width"][i]
                        h = boxes["height"][i]
                        # Draw redaction rectangle
                        draw.rectangle([(x, y), (x + w, y + h)], fill=color_fill)

            # Save redacted image
            pil_image.save(output_path)

            return {
                "status": "success",
                "detected_entities": [e["text"] for e in detected_entities],
                "entity_types": list(set(e["type"] for e in detected_entities)),
                "output_path": output_path,
            }

        except Exception as e:
            self.logger.error(f"Error during image redaction: {str(e)}")
            raise
