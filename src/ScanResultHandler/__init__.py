import os
import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient
from urllib.parse import urlparse
import logging
from datetime import datetime

async def main(event: func.EventGridEvent):
    """Handles scan results"""
    try:
        logging.info(f'Processing scan result for: {event.subject}')
        data = event.get_json()
        blob_url = data['subject']
        scan_result = data['data']
        
        if os.environ.get('UPDATE_BLOB_METADATA') == 'Yes':
            await update_blob_metadata(blob_url, scan_result)
            logging.info(f'Successfully updated metadata for: {blob_url}')
    except Exception as e:
        logging.error(f'Error processing scan result: {str(e)}')
        raise

async def update_blob_metadata(blob_url: str, scan_result: dict):
    """Update blob metadata with scan results"""
    try:
        credential = DefaultAzureCredential()
        
        # Parse blob URL
        parsed = urlparse(blob_url)
        account = parsed.netloc.split('.')[0]
        path_parts = parsed.path.split('/')
        container = path_parts[1]
        blob_name = '/'.join(path_parts[2:])
        
        # Update metadata and tags
        blob_service = BlobServiceClient(
            f"https://{account}.blob.core.windows.net",
            credential=credential
        )
        blob_client = blob_service.get_blob_client(container, blob_name)
        
        # Prepare metadata
        metadata = {
            'scanStatus': scan_result['status'],
            'scanTimestamp': datetime.utcnow().isoformat(),
            'scanEngine': scan_result.get('engine', 'default'),
            'scanVersion': scan_result.get('version', '1.0')
        }
        
        # Prepare tags
        tags = {
            'scan:status': scan_result['status'],
            'scan:timestamp': datetime.utcnow().isoformat(),
            'scan:engine': scan_result.get('engine', 'default'),
            'scan:version': scan_result.get('version', '1.0')
        }
        
        # Add any findings if present
        if 'findings' in scan_result:
            metadata['scanFindings'] = str(scan_result['findings'])
            tags['scan:findings'] = str(scan_result['findings'])
        
        await blob_client.set_blob_metadata(metadata)
        await blob_client.set_blob_tags(tags)
        
    except Exception as e:
        logging.error(f'Error updating blob metadata: {str(e)}')
        raise