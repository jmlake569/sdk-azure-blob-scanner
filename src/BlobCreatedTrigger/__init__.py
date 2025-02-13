import logging
import json
import azure.functions as func
from datetime import datetime, timedelta
from azure.storage.blob import generate_blob_sas, BlobSasPermissions
import os

def main(event: func.EventGridEvent, outputQueueItem: func.Out[str]) -> None:
    logging.info(f'Event: {event.get_json()}')
    
    try:
        data = event.get_json()
        url = data.get('url')
        
        if not url:
            raise ValueError("No URL in event data")
            
        url_parts = url.split('/')
        account_name = url_parts[2].split('.')[0]
        container_name = url_parts[-2]
        blob_name = url_parts[-1]
        
        # Generate SAS URL
        account_key = os.environ["STORAGE_ACCOUNT_KEY"]
        sas_token = generate_blob_sas(
            account_name=account_name,
            container_name=container_name,
            blob_name=blob_name,
            account_key=account_key,
            permission=BlobSasPermissions(read=True),
            expiry=datetime.utcnow() + timedelta(hours=1)
        )
        
        sas_url = f"https://{account_name}.blob.core.windows.net/{container_name}/{blob_name}?{sas_token}"
        
        scan_request = {
            'blob_url': sas_url,
            'blob_name': blob_name,
            'container': container_name,
            'content_type': data.get('contentType'),
            'size': data.get('contentLength'),
            'submitted_at': datetime.utcnow().isoformat()
        }
        
        outputQueueItem.set(json.dumps(scan_request))
        logging.info(f'Queued scan request for {blob_name}')
        
    except Exception as e:
        logging.error(f'Error processing event: {str(e)}')
        raise