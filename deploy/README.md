# Azure Function Malware Scanner Setup Guide

## Function Deployment

### 1. Create ZIP Package

```sh
zip -r .function.zip . -x ".*" -x "__MACOSX" -x "*.pyc"
```

### 2. Create Function App in Azure Portal
1. Navigate to [Azure Portal](https://portal.azure.com)
2. Sign in with your Azure account
3. Click "Create a resource"
4. Search for "Function App"
5. Click "Create" on the Function App card

### 3. Configure Basic Settings
* **Subscription**: Select your subscription
* **Resource Group**: Create new or select existing
* **Function App name**: Enter a globally unique name
* **Publish**: Code
* **Runtime stack**: Python
* **Version**: 3.11
* **Region**: Select your preferred region
* **Operating System**: Linux
* **Plan type**: Consumption (Serverless)

### 4. Deploy Function Code

Upload the function code:
```sh
az functionapp deployment source config-zip --resource-group <your_resource_group> --name ScannerFunction --src ./function.zip
```

Set the environment variables:
```sh
az functionapp config appsettings set \
--name ScannerFunction \
--resource-group <your_resource_group> \
--settings \
AMAAS_REGION="us-east-1" \
AMAAS_API_KEY="your_api_key_here"
```

```sh
set the storage account key for access:
az functionapp config appsettings set \
--name ScannerFunction \
--resource-group <your_resource_group> \
--settings STORAGE_ACCOUNT_KEY="your_storage_account_key_here"
```

### 5. Set Up Event Grid and Topic

1. In the Azure Portal, click "Create a resource"
2. Search for "Event Grid Topic" and select it
3. Click "Create"

#### Basic Settings
* **Subscription**: Select your subscription
* **Resource Group**: Use the same resource group as your function
* **Name**: Choose a unique name for your topic
* **Location**: Use the same region as your function

#### Link Storage Account to Event Grid
1. Go to your Storage Account
2. Click "Events" in the left menu
3. Click "+ Event Subscription"
4. Configure:
   * **Name**: Choose a descriptive name
   * **Event Schema**: Event Grid Schema
   * **System Topic Name**: Create new or select existing
   * **Event Types**: Select "Blob Created"
   * **Endpoint Type**: Azure Function
   * **Endpoint**: Select your function app and function

Your Event Grid is now configured to trigger your function when new blobs are created in the storage account.
