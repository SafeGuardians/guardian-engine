import fitz
import json
import os
import uuid
import requests
from datetime import datetime
from typing import Dict, Any, Optional
from cryptography.fernet import Fernet
import logging

logger = logging.getLogger("guardian-analyzer")

class DRMPDFManager:
    def __init__(self, api_url: str):
        """Initialize DRM PDF Manager"""
        self.api_url = api_url
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)
        
    def create_drm_pdf(
        self,
        input_path: str,
        output_path: str,
        owner_id: str,
        expiry_date: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """Create a DRM-protected PDF"""
        try:
            # Generate unique document ID
            doc_id = str(uuid.uuid4())
            
            # Create JavaScript action for the PDF
            verify_script = f"""
            try {{
                var xhr = new XMLHttpRequest();
                xhr.open('GET', '{self.api_url}/verify?doc_id={doc_id}', false);
                xhr.send(null);
                
                if (xhr.status !== 200) {{
                    app.alert('Access to this document has been revoked.');
                    this.closeDoc(true);
                }}
            }} catch (e) {{
                app.alert('Unable to verify document access. Please check your internet connection.');
            }}
            """
            
            # Open and modify the PDF
            doc = fitz.open(input_path)
            
            # Add JavaScript to be executed when document opens
            doc.js_onCreate = verify_script
            
            # Add JavaScript to be executed periodically
            doc.js_onIdle = verify_script
            
            # Encrypt the document with standard protection
            doc.save(
                output_path,
                encryption=fitz.PDF_ENCRYPT_AES_256,
                owner_pw=self.key.decode(),  # Owner password
                user_pw="",                  # Empty user password for automatic checks
                permissions=fitz.PDF_PERM_ACCESSIBILITY  # Minimal permissions
            )
            
            # Store DRM metadata in our system
            drm_metadata = {
                'doc_id': doc_id,
                'owner_id': owner_id,
                'creation_date': datetime.now().isoformat(),
                'expiry_date': expiry_date.isoformat() if expiry_date else None,
                'status': 'active'
            }
            
            # Save metadata to database or file system
            self._store_metadata(doc_id, drm_metadata)
            
            return {
                'status': 'success',
                'doc_id': doc_id,
                'output_path': output_path
            }
            
        except Exception as e:
            logger.error(f"Error creating DRM PDF: {str(e)}")
            raise

    def revoke_access(self, doc_id: str, owner_id: str) -> Dict[str, Any]:
        """Revoke access to a DRM-protected PDF"""
        try:
            # Update DRM status on server
            response = requests.post(f"{self.api_url}/revoke", 
                json={'doc_id': doc_id, 'owner_id': owner_id})
            
            if response.status_code == 200:
                return {'status': 'success', 'message': 'Access revoked successfully'}
            else:
                raise Exception(f"Failed to revoke access: {response.text}")
                
        except Exception as e:
            logger.error(f"Error revoking access: {str(e)}")
            raise

    def open_drm_pdf(self, drm_path: str) -> fitz.Document:
        """Open and verify a DRM-protected PDF"""
        try:
            # Read DRM container
            with open(drm_path, 'r') as f:
                drm_container = json.load(f)
            
            metadata = drm_container['metadata']
            
            # Verify access with server
            response = requests.get(f"{self.api_url}/verify",
                params={'doc_id': metadata['doc_id']})
            
            if response.status_code != 200:
                raise Exception("Access denied or revoked")
            
            # Decrypt content
            cipher_suite = Fernet(metadata['encryption_key'].encode())
            decrypted_data = cipher_suite.decrypt(drm_container['content'].encode())
            
            # Create temporary file for PyMuPDF
            temp_path = f"/tmp/{metadata['doc_id']}.pdf"
            with open(temp_path, 'wb') as f:
                f.write(decrypted_data)
            
            # Open with PyMuPDF
            doc = fitz.open(temp_path)
            os.remove(temp_path)  # Clean up
            
            return doc
            
        except Exception as e:
            logger.error(f"Error opening DRM PDF: {str(e)}")
            raise 