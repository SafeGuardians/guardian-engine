"""REST API server for analyzer."""

import json
import logging
import os
import time
from logging.config import fileConfig
from pathlib import Path
from typing import Tuple
import numpy as np

from flask import Flask, Response, jsonify, request, send_file
from guardian_analyzer import AnalyzerEngine, AnalyzerEngineProvider, AnalyzerRequest
from werkzeug.exceptions import HTTPException

from werkzeug.utils import secure_filename

from new_pdf_redactor import GuardianPDFRedactor

# from adv_pdf_redactor import AdvancedPDFRedactor
from image_redactor import PresidioImageRedactor

DEFAULT_PORT = "3000"

LOGGING_CONF_FILE = "logging.ini"

WELCOME_MESSAGE = r"""
 ____         __       ____                     _
/ ___|  __ _ / _| ___ / ___|_   _  __ _ _ __ __| (_) __ _ _ __  ___
\___ \ / _` | |_ / _ \ |  _| | | |/ _` | '__/ _` | |/ _` | '_ \/ __|
 ___) | (_| |  _|  __/ |_| | |_| | (_| | | | (_| | | (_| | | | \__ \
|____/ \__,_|_|  \___|\____|\__,_|\__,_|_|  \__,_|_|\__,_|_| |_|___/

"""


class Server:
    """HTTP Server for calling Presidio Analyzer."""

    def __init__(self):
        fileConfig(Path(Path(__file__).parent, LOGGING_CONF_FILE))
        self.logger = logging.getLogger("guardian-analyzer")
        self.logger.setLevel(os.environ.get("LOG_LEVEL", self.logger.level))
        self.app = Flask(__name__)

        analyzer_conf_file = os.environ.get("ANALYZER_CONF_FILE")
        nlp_engine_conf_file = os.environ.get("NLP_CONF_FILE")
        recognizer_registry_conf_file = os.environ.get("RECOGNIZER_REGISTRY_CONF_FILE")

        self.logger.info("Starting analyzer engine")
        self.engine: AnalyzerEngine = AnalyzerEngineProvider(
            analyzer_engine_conf_file=analyzer_conf_file,
            nlp_engine_conf_file=nlp_engine_conf_file,
            recognizer_registry_conf_file=recognizer_registry_conf_file,
        ).create_engine()
        self.pdf_redactor = GuardianPDFRedactor(analyzer_engine=self.engine)
        # self.pdf_redactor = AdvancedPDFRedactor()
        print(WELCOME_MESSAGE)

        self.image_redactor = PresidioImageRedactor()

        @self.app.route("/health")
        def health() -> str:
            """Return basic health probe result."""
            return "Presidio Analyzer service is up"

        # # New route to extract PII entities with their text
        #
        # @self.app.route("/pii-entities", methods=["POST"])
        # def get_pii_entities() -> Tuple[str, int]:
        #     """Extract PII entities with their text snippets."""
        #     try:
        #         req_data = AnalyzerRequest(request.get_json())
        #         if not req_data.text:
        #             raise Exception("No text provided")
        #         if not req_data.language:
        #             raise Exception("No language provided")
        #
        #         # Perform analysis
        #         recognizer_result_list = self.engine.analyze(
        #             text=req_data.text,
        #             language=req_data.language,
        #             # Use same parameters as analyze method
        #             correlation_id=req_data.correlation_id,
        #             score_threshold=req_data.score_threshold,
        #             entities=req_data.entities,
        #             return_decision_process=req_data.return_decision_process,
        #             ad_hoc_recognizers=req_data.ad_hoc_recognizers,
        #             context=req_data.context,
        #             allow_list=req_data.allow_list,
        #             allow_list_match=req_data.allow_list_match,
        #             regex_flags=req_data.regex_flags,
        #         )
        #
        #         pii_entities = [
        #             {
        #                 "entity_type": entity.entity_type,
        #                 "text_snippet": req_data.text[entity.start : entity.end],
        #                 "score": entity.score,
        #             }
        #             for entity in recognizer_result_list
        #             if entity.entity_type
        #             in ["PERSON", "LOCATION", "PHONE_NUMBER", "ID"]
        #         ]
        #
        #         return Response(
        #             json.dumps(
        #                 pii_entities,
        #                 sort_keys=True,
        #             ),
        #             content_type="application/json",
        #         )
        #     except TypeError as te:
        #         error_msg = f"Failed to parse /pii-entities request. {te.args[0]}"
        #         self.logger.error(error_msg)
        #         return jsonify(error=error_msg), 400
        #     except Exception as e:
        #         self.logger.error(
        #             f"A fatal error occurred during PII entity extraction. {e}"
        #         )
        #         return jsonify(error=e.args[0]), 500
        #
        @self.app.route("/analyze", methods=["POST"])
        def analyze() -> Tuple[str, int]:
            """Execute the analyzer function."""
            # Parse the request params
            try:
                # TODO: ADD MORE RECOGNIZERS
                print(request.get_json())
                req_data = AnalyzerRequest(request.get_json())
                if not req_data.text:
                    raise Exception("No text provided")

                if not req_data.language:
                    raise Exception("No language provided")

                recognizer_result_list = self.engine.analyze(
                    text=req_data.text,
                    language=req_data.language,
                    correlation_id=req_data.correlation_id,
                    score_threshold=req_data.score_threshold,
                    entities=req_data.entities,
                    return_decision_process=req_data.return_decision_process,
                    ad_hoc_recognizers=req_data.ad_hoc_recognizers,
                    context=req_data.context,
                    allow_list=req_data.allow_list,
                    allow_list_match=req_data.allow_list_match,
                    regex_flags=req_data.regex_flags,
                )

                self.logger.info(f"Hello {type(recognizer_result_list)} results.")
                self.logger.info(f"Hi {recognizer_result_list} results.")

                def custom_serializer(obj):
                    if isinstance(obj, (np.float32, np.float64)):
                        return float(obj)

                    if hasattr(obj, "to_dict"):
                        return obj.to_dict()

                    raise TypeError(
                        f"Object of type {type(obj)} is not JSON serializable"
                    )

                pii_entities = [
                    {
                        "entity_type": entity.entity_type,
                        "text_snippet": req_data.text[entity.start : entity.end],
                        "score": entity.score,
                    }
                    for entity in recognizer_result_list
                ]

                return Response(
                    json.dumps(
                        pii_entities,
                        # default=lambda o: o.to_dict(),
                        default=custom_serializer,
                        sort_keys=True,
                    ),
                    content_type="application/json",
                )
            except TypeError as te:
                error_msg = (
                    f"Failed to parse /analyze request "
                    f"for AnalyzerEngine.analyze(). {te.args[0]}"
                )
                self.logger.error(error_msg)
                return jsonify(error=error_msg), 400

            except Exception as e:
                self.logger.error(
                    f"A fatal error occurred during execution of "
                    f"AnalyzerEngine.analyze(). {e}"
                )
                return jsonify(error=e.args[0]), 500

        @self.app.route("/recognizers", methods=["GET"])
        def recognizers() -> Tuple[str, int]:
            """Return a list of supported recognizers."""
            language = request.args.get("language")
            try:
                recognizers_list = self.engine.get_recognizers(language)
                names = [o.name for o in recognizers_list]
                return jsonify(names), 200
            except Exception as e:
                self.logger.error(
                    f"A fatal error occurred during execution of "
                    f"AnalyzerEngine.get_recognizers(). {e}"
                )
                return jsonify(error=e.args[0]), 500

        @self.app.route("/supportedentities", methods=["GET"])
        def supported_entities() -> Tuple[str, int]:
            """Return a list of supported entities."""
            language = request.args.get("language")
            try:
                entities_list = self.engine.get_supported_entities(language)
                return jsonify(entities_list), 200
            except Exception as e:
                self.logger.error(
                    f"A fatal error occurred during execution of "
                    f"AnalyzerEngine.supported_entities(). {e}"
                )
                return jsonify(error=e.args[0]), 500

        @self.app.route("/redact-pdf", methods=["POST"])
        def redact_pdf():
            try:
                if "file" not in request.files:
                    return jsonify({"error": "No file provided"}), 400

                file = request.files["file"]
                if file.filename == "":
                    return jsonify({"error": "No file selected"}), 400

                # Get parameters
                language = request.form.get("language", "en")

                # Parse and validate entities
                try:
                    entities = json.loads(request.form.get("entities", "[]"))
                    if not isinstance(entities, list):
                        return jsonify({"error": "Entities must be a list"}), 400
                except json.JSONDecodeError:
                    return jsonify({"error": "Invalid entities JSON"}), 400

                additional_keywords = request.form.getlist("additional_keywords")
                custom_regex = request.form.getlist("custom_regex")

                # Create unique filenames
                timestamp = int(time.time())
                input_filename = secure_filename(file.filename)
                input_path = os.path.join("temp/input", f"{timestamp}_{input_filename}")
                output_filename = f"redacted_{timestamp}_{input_filename}"
                output_path = os.path.join("temp/output", output_filename)

                # Save uploaded file
                file.save(input_path)

                try:
                    # Process the PDF
                    result = self.pdf_redactor.redact_pdf(
                        pdf_path=input_path,
                        output_path=output_path,
                        language=language,
                        additional_keywords=additional_keywords,
                        custom_regex=custom_regex,
                        entities=entities,
                    )

                    self.logger.info(f"Redaction completed: {result}")

                    # Return the redacted PDF
                    return send_file(
                        output_path,
                        as_attachment=True,
                        download_name=output_filename,
                        mimetype="application/pdf",
                    )

                finally:
                    # Cleanup temporary files
                    try:
                        if os.path.exists(input_path):
                            os.remove(input_path)
                        if os.path.exists(output_path):
                            # Only remove after sending file
                            pass
                    except Exception as e:
                        self.logger.warning(f"Error cleaning up temporary files: {e}")

            except Exception as e:
                self.logger.error(f"Error processing PDF: {e}")
                return (
                    jsonify({"error": str(e), "message": "Failed to process PDF"}),
                    500,
                )

        # def redact_pdf():
        #     """
        #     Endpoint to analyze and redact PDF files
        #     """
        #     try:
        #         # Validate request
        #         if "file" not in request.files:
        #             raise Exception("No file provided")
        #
        #         file = request.files["file"]
        #         if file.filename == "":
        #             raise Exception("No file selected")
        #
        #         # Get parameters
        #         language = request.form.get("language", "en")
        #         additional_keywords = request.form.getlist("additional_keywords")
        #         custom_regex = request.form.getlist("custom_regex")
        #
        #         # Create temporary directories if they don't exist
        #         os.makedirs("temp/input", exist_ok=True)
        #         os.makedirs("temp/output", exist_ok=True)
        #
        #         # Save input file
        #         input_filename = secure_filename(file.filename)
        #         input_path = os.path.join("temp/input", input_filename)
        #         file.save(input_path)
        #
        #         # Create output path
        #         output_filename = f"redacted_{input_filename}"
        #         output_path = os.path.join("temp/output", output_filename)
        #
        #         # Process the PDF
        #         result = self.pdf_redactor.redact_pdf(
        #             pdf_path=input_path,
        #             output_path=output_path,
        #             language=language,
        #             additional_keywords=additional_keywords,
        #             custom_regex=custom_regex,
        #         )
        #
        #         # Return the redacted PDF file
        #         return send_file(
        #             output_path,
        #             as_attachment=True,
        #             download_name=output_filename,
        #             mimetype="application/pdf",
        #         )
        #
        #     except Exception as e:
        #         self.logger.error(f"Error redacting PDF: {e}")
        #         return jsonify(error=str(e)), 500
        #
        #     finally:
        #         # Cleanup temporary files
        #         try:
        #             if "input_path" in locals():
        #                 os.remove(input_path)
        #             if "output_path" in locals():
        #                 os.remove(output_path)
        #         except Exception as e:
        #             self.logger.warning(f"Error cleaning up temporary files: {e}")

        @self.app.route("/redact-image", methods=["POST"])
        def redact_image():
            try:
                if "file" not in request.files:
                    return jsonify({"error": "No file provided"}), 400

                file = request.files["file"]
                if file.filename == "":
                    return jsonify({"error": "No file selected"}), 400

                # Validate file type
                allowed_extensions = {"png", "jpg", "jpeg"}
                if not file.filename.lower().endswith(tuple(allowed_extensions)):
                    return jsonify({"error": "Invalid file type"}), 400

                # Get parameters
                language = request.form.get("language", "en")

                # Parse and validate entities
                try:
                    entities = json.loads(request.form.get("entities", "[]"))
                    if not isinstance(entities, list):
                        return jsonify({"error": "Entities must be a list"}), 400
                except json.JSONDecodeError:
                    return jsonify({"error": "Invalid entities JSON"}), 400

                # Create unique filenames
                timestamp = int(time.time())
                input_filename = secure_filename(file.filename)
                input_path = os.path.join("temp/input", f"{timestamp}_{input_filename}")
                output_filename = f"redacted_{timestamp}_{input_filename}"
                output_path = os.path.join("temp/output", output_filename)

                # Ensure directories exist
                os.makedirs(os.path.dirname(input_path), exist_ok=True)
                os.makedirs(os.path.dirname(output_path), exist_ok=True)

                # Save uploaded file
                file.save(input_path)

                try:
                    # Process the image
                    result = self.image_redactor.redact_image(
                        image_path=input_path,
                        output_path=output_path,
                        language=language,
                        entities=entities,
                    )

                    # Return the redacted image
                    return send_file(
                        output_path,
                        as_attachment=True,
                        download_name=output_filename,
                        mimetype=f"image/{output_filename.split('.')[-1].lower()}",
                    )

                finally:
                    # Cleanup temporary files
                    try:
                        if os.path.exists(input_path):
                            os.remove(input_path)
                        if os.path.exists(output_path):
                            # Only remove after sending file
                            pass
                    except Exception as e:
                        self.logger.warning(f"Error cleaning up temporary files: {e}")

            except Exception as e:
                self.logger.error(f"Error processing image: {e}")
                return (
                    jsonify({"error": str(e), "message": "Failed to process image"}),
                    500,
                )

        @self.app.errorhandler(HTTPException)
        def http_exception(e):
            return jsonify(error=e.description), e.code


if __name__ == "__main__":
    port = int(os.environ.get("PORT", DEFAULT_PORT))
    server = Server()
    server.app.run(host="0.0.0.0", port=port, debug=True)
