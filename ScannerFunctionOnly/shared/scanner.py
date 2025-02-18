import logging
import os
import tempfile
from typing import Dict, Any, Optional
import amaas.grpc
from datetime import datetime
import json
import requests

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ScanResult:
    """Represents the result of a malware scan"""
    def __init__(self, is_clean: bool, details: Dict[str, Any], error: Optional[str] = None):
        self.is_clean = is_clean
        self.details = details
        self.error = error
        self.timestamp = datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        return {
            'is_clean': self.is_clean,
            'details': self.details,
            'error': self.error,
            'timestamp': str(self.timestamp)
        }

class Scanner:
    """Handles file scanning operations"""
    def __init__(self):
        self.region = os.environ["AMAAS_REGION"]
        self.api_key = os.environ["AMAAS_API_KEY"]
        
    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass
        
    def scan_file(self, file_path, original_filename=None):
        if not os.environ.get("AMAAS_REGION"):
            raise ValueError("AMAAS_REGION environment variable must be set")
        if not os.environ.get("AMAAS_API_KEY"):
            raise ValueError("AMAAS_API_KEY environment variable must be set")
            
        # Use original filename if provided, otherwise use the temp file name
        filename = original_filename or os.path.basename(file_path)
        logging.info(f"Scanning file {filename} from path {file_path}")
        
        url = f"https://{self.region}.api.insight.rapid7.com/ias/v1/scan"
        headers = {"X-Api-Key": self.api_key}
        
        with open(file_path, "rb") as f:
            # Important: Use the original filename in the files dictionary
            files = {"file": (filename, f, "application/octet-stream")}
            response = requests.post(url, headers=headers, files=files)
            
        timestamp = datetime.datetime.now()
        
        if response.status_code != 200:
            error = f"Scan failed with status {response.status_code}: {response.text}"
            logging.error(error)
            return {
                "is_clean": False,
                "details": None,
                "error": error,
                "timestamp": timestamp
            }
            
        try:
            scan_results = response.json()
            # Update the filename in the scan results to use the original filename
            if isinstance(scan_results, dict):
                scan_results["fileName"] = filename
                
            is_clean = scan_results.get("result", {}).get("atse", {}).get("malwareCount", 1) == 0
            
            return {
                "is_clean": is_clean,
                "details": {
                    "raw_results": json.dumps(scan_results),
                    "file_path": file_path,
                    "original_filename": filename,
                    "file_size": os.path.getsize(file_path)
                },
                "error": None,
                "timestamp": timestamp
            }
            
        except Exception as e:
            error = f"Failed to parse scan results: {str(e)}"
            logging.error(error)
            return {
                "is_clean": False,
                "details": None,
                "error": error,
                "timestamp": timestamp
            }

    def scan_stream(self, stream, file_name: str) -> Dict[str, Any]:
        try:
            scan_results = amaas.grpc.scan_stream(
                channel=self.handle,
                stream=stream,
                file_name=file_name,
                pml=True,
                verbose=True,
                digest=True
            )
            
            details = {
                'raw_results': scan_results,
                'file_name': file_name
            }
            
            is_clean = True
            if isinstance(scan_results, dict):
                result = scan_results.get('result', {})
                total_malware = (
                    result.get('atse', {}).get('malwareCount', 0) +
                    result.get('trendx', {}).get('malwareCount', 0)
                )
                is_clean = total_malware == 0
            
            return {
                'is_clean': is_clean,
                'details': details,
                'error': None,
                'timestamp': str(datetime.utcnow())
            }
            
        except Exception as e:
            logger.error(f"Scanning failed: {str(e)}")
            return {
                'is_clean': False,
                'details': {},
                'error': str(e),
                'timestamp': str(datetime.utcnow())
            }