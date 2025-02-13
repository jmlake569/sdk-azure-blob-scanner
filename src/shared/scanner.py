import logging
import os
import tempfile
from typing import Dict, Any, Optional
import amaas.grpc
from datetime import datetime

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
    def __init__(self, settings: Optional[Dict[str, Any]] = None):
        self.settings = settings or {
            'region': os.getenv('AMAAS_REGION'),
            'api_key': os.getenv('AMAAS_API_KEY'),
            'tls': True,
            'ca_cert': None
        }
        self._validate_settings()
        self.handle = None

    def _validate_settings(self):
        if not self.settings.get('region'):
            raise ValueError("AMAAS_REGION environment variable must be set")
        if not self.settings.get('api_key'):
            raise ValueError("AMAAS_API_KEY environment variable must be set")

    def __enter__(self):
        self.handle = amaas.grpc.init_by_region(
            self.settings['region'],
            self.settings['api_key'],
            self.settings.get('tls', False),
            self.settings.get('ca_cert')
        )
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.handle:
            try:
                amaas.grpc.quit(self.handle)
            except Exception as e:
                logger.error(f"Error closing scanner handle: {str(e)}")
            finally:
                self.handle = None

    def scan_file(self, file_path: str, verbose: bool = True) -> ScanResult:
        if not os.path.exists(file_path):
            return ScanResult(
                is_clean=False,
                details={},
                error=f"File not found: {file_path}"
            )

        try:
            scan_results = amaas.grpc.scan_file(
                channel=self.handle,
                file_name=file_path,
                pml=True,
                verbose=verbose,
                digest=True
            )
            
            details = {
                'raw_results': scan_results,
                'file_path': file_path,
                'file_size': os.path.getsize(file_path)
            }
            
            is_clean = True
            if isinstance(scan_results, dict):
                result = scan_results.get('result', {})
                total_malware = (
                    result.get('atse', {}).get('malwareCount', 0) +
                    result.get('trendx', {}).get('malwareCount', 0)
                )
                is_clean = total_malware == 0
            
            return ScanResult(
                is_clean=is_clean,
                details=details
            )

        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {str(e)}")
            return ScanResult(
                is_clean=False,
                details={},
                error=str(e)
            )

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