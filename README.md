# HashDB API Hash Lookup Plugin for IDA Pro

This IDA Pro plugin calculates the hash values of opened files and queries these hash values through the HashDB API.

## Features

- Calculates MD5, SHA1, and SHA256 hash values of the opened file
- Queries the MD5 hash value on HashDB API
- Displays results on a graphical interface

## Installation

1. Download `hashdb_plugin.py` and `requirements.txt` files
2. Install required dependencies: `pip install -r requirements.txt`
3. Copy `hashdb_plugin.py` file to IDA Pro's plugins directory:
   - Windows: `%APPDATA%\Hex-Rays\IDA Pro\plugins`
   - Linux: `~/.idapro/plugins`
   - macOS: `~/Library/Application Support/IDA Pro/plugins`

## Usage

1. Open a binary file in IDA Pro
2. Select Edit > Plugins > HashDB Lookup menu or use the `Ctrl+Alt+H` shortcut
3. Enter your API Key in the opened window
4. Click the "Query Hash Value" button

## Configuration

To configure the HashDB API URL, edit the `HASHDB_API_URL` variable in the `hashdb_plugin.py` file:

```python
HASHDB_API_URL = "https://hashdb-api.example.com/api/v1"  # Replace with the actual API URL
```

## Requirements

- IDA Pro 7.0 or above
- Python 3.x
- PyQt5
- requests
