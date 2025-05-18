"""
HashDB API Hash Lookup Plugin for IDA Pro
Author: [majorka]
Github: [https://github.com/majorkadev]
"""

import idaapi
import idautils
import idc
import requests
import json
import hashlib
from PyQt5 import QtCore, QtWidgets

# HashDB API URL
HASHDB_API_URL = "https://hashdb-api.example.com/api/v1"  # Need to be changed - with actual API URL

# API query types
HASH_TYPES = {
    "md5": "MD5",
    "sha1": "SHA1",
    "sha256": "SHA256"
}

class HashDBLookup(idaapi.plugin_t):
    flags = idaapi.PLUGIN_UNL
    comment = "Hash query with HashDB API"
    help = "Query file hash value on HashDB API"
    wanted_name = "HashDB Lookup"
    wanted_hotkey = "Ctrl-Alt-H"
    
    def init(self):
        # Add plugin menu
        self.menu_context = idaapi.add_menu_item("Edit/Plugins/", "HashDB Lookup", "Ctrl-Alt-H", 0, self.run, None)
        return idaapi.PLUGIN_OK
    
    def run(self, arg):
        # Plugin main function
        HashDBForm().exec_()
    
    def term(self):
        # Plugin termination, clean menu
        if self.menu_context:
            idaapi.del_menu_item(self.menu_context)
        return None

class HashAPIClient:
    """HashDB API client"""
    
    def __init__(self, api_key, base_url=HASHDB_API_URL):
        self.api_key = api_key
        self.base_url = base_url
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
    
    def lookup_hash(self, hash_value, hash_type="md5"):
        """Query hash value on API"""
        try:
            response = requests.get(
                f"{self.base_url}/lookup/{hash_type}/{hash_value}", 
                headers=self.headers
            )
            return response
        except Exception as e:
            return {"error": str(e)}
    
    def submit_hash(self, hash_data):
        """Submit new hash information to API"""
        try:
            response = requests.post(
                f"{self.base_url}/submit", 
                headers=self.headers,
                json=hash_data
            )
            return response
        except Exception as e:
            return {"error": str(e)}

class HashDBForm(QtWidgets.QDialog):
    def __init__(self):
        super(HashDBForm, self).__init__()
        self.setup_ui()
        
    def setup_ui(self):
        # UI elements
        self.setWindowTitle("HashDB API Hash Lookup")
        self.resize(600, 400)
        
        layout = QtWidgets.QVBoxLayout()
        
        # File hash information
        hash_group = QtWidgets.QGroupBox("File Hash Values")
        hash_layout = QtWidgets.QFormLayout()
        self.md5_label = QtWidgets.QLabel("N/A")
        self.sha1_label = QtWidgets.QLabel("N/A")
        self.sha256_label = QtWidgets.QLabel("N/A")
        
        hash_layout.addRow("MD5:", self.md5_label)
        hash_layout.addRow("SHA1:", self.sha1_label)
        hash_layout.addRow("SHA256:", self.sha256_label)
        hash_group.setLayout(hash_layout)
        
        # Query section
        query_group = QtWidgets.QGroupBox("HashDB API Query")
        query_layout = QtWidgets.QVBoxLayout()
        
        self.api_key_input = QtWidgets.QLineEdit()
        query_layout.addWidget(QtWidgets.QLabel("API Key:"))
        query_layout.addWidget(self.api_key_input)
        
        # Hash type selection
        hash_type_layout = QtWidgets.QHBoxLayout()
        hash_type_layout.addWidget(QtWidgets.QLabel("Hash Type:"))
        self.hash_type_combo = QtWidgets.QComboBox()
        for hash_type, hash_name in HASH_TYPES.items():
            self.hash_type_combo.addItem(hash_name, hash_type)
        hash_type_layout.addWidget(self.hash_type_combo)
        query_layout.addLayout(hash_type_layout)
        
        self.search_button = QtWidgets.QPushButton("Query Hash Value")
        self.search_button.clicked.connect(self.lookup_hash)
        query_layout.addWidget(self.search_button)
        
        # Hash submission section
        submit_layout = QtWidgets.QHBoxLayout()
        self.file_name_input = QtWidgets.QLineEdit()
        self.file_name_input.setPlaceholderText("File name (optional)")
        submit_layout.addWidget(self.file_name_input)
        
        self.submit_button = QtWidgets.QPushButton("Submit Hash Information")
        self.submit_button.clicked.connect(self.submit_hash_info)
        submit_layout.addWidget(self.submit_button)
        
        query_layout.addLayout(submit_layout)
        query_group.setLayout(query_layout)
        
        # Results section
        result_group = QtWidgets.QGroupBox("Results")
        result_layout = QtWidgets.QVBoxLayout()
        self.result_text = QtWidgets.QTextEdit()
        self.result_text.setReadOnly(True)
        result_layout.addWidget(self.result_text)
        result_group.setLayout(result_layout)
        
        layout.addWidget(hash_group)
        layout.addWidget(query_group)
        layout.addWidget(result_group)
        
        button_layout = QtWidgets.QHBoxLayout()
        self.close_button = QtWidgets.QPushButton("Close")
        self.close_button.clicked.connect(self.close)
        button_layout.addWidget(self.close_button)
        
        layout.addLayout(button_layout)
        self.setLayout(layout)
        
        # Get file hash values
        self.calculate_hashes()
        
        # Hash values
        self.hashes = {
            "md5": "",
            "sha1": "",
            "sha256": ""
        }
    
    def calculate_hashes(self):
        """Calculate hash values of the file opened in IDA"""
        try:
            input_file = idaapi.get_input_file_path()
            
            with open(input_file, 'rb') as f:
                data = f.read()
                md5_hash = hashlib.md5(data).hexdigest()
                sha1_hash = hashlib.sha1(data).hexdigest()
                sha256_hash = hashlib.sha256(data).hexdigest()
            
            self.md5_label.setText(md5_hash)
            self.sha1_label.setText(sha1_hash)
            self.sha256_label.setText(sha256_hash)
            
            # Save hash values
            self.hashes["md5"] = md5_hash
            self.hashes["sha1"] = sha1_hash
            self.hashes["sha256"] = sha256_hash
            
        except Exception as e:
            idaapi.warning(f"Error calculating hash: {str(e)}")
    
    def get_api_client(self):
        """Create API client"""
        api_key = self.api_key_input.text().strip()
        if not api_key:
            self.result_text.setText("API Key required!")
            return None
        return HashAPIClient(api_key)
    
    def lookup_hash(self):
        """Query hash value"""
        try:
            api_client = self.get_api_client()
            if not api_client:
                return
                
            # Get selected hash type
            hash_type = self.hash_type_combo.currentData()
            hash_value = self.hashes[hash_type]
            
            if not hash_value:
                self.result_text.setText(f"{hash_type.upper()} hash value could not be calculated!")
                return
            
            # Make API request
            response = api_client.lookup_hash(hash_value, hash_type)
            
            if hasattr(response, 'status_code') and response.status_code == 200:
                result = response.json()
                formatted_result = json.dumps(result, indent=4)
                self.result_text.setText(formatted_result)
            elif hasattr(response, 'status_code'):
                self.result_text.setText(f"Error: {response.status_code}\n{response.text}")
            else:
                self.result_text.setText(f"Error: {response}")
                
        except Exception as e:
            self.result_text.setText(f"Error during query: {str(e)}")
    
    def submit_hash_info(self):
        """Submit hash information to API"""
        try:
            api_client = self.get_api_client()
            if not api_client:
                return
            
            file_name = self.file_name_input.text().strip()
            if not file_name:
                file_name = idaapi.get_input_file_path()
                file_name = file_name.split("/")[-1] if "/" in file_name else file_name.split("\\")[-1]
            
            # Create hash information
            hash_data = {
                "file_name": file_name,
                "md5": self.hashes["md5"],
                "sha1": self.hashes["sha1"],
                "sha256": self.hashes["sha256"],
                "info": {
                    "analysis_platform": "IDA Pro",
                    "submitted_by": "HashDB Plugin"
                }
            }
            
            # Make API request
            response = api_client.submit_hash(hash_data)
            
            if hasattr(response, 'status_code') and response.status_code in [200, 201]:
                result = response.json()
                formatted_result = json.dumps(result, indent=4)
                self.result_text.setText("Hash information successfully submitted:\n" + formatted_result)
            elif hasattr(response, 'status_code'):
                self.result_text.setText(f"Error: {response.status_code}\n{response.text}")
            else:
                self.result_text.setText(f"Error: {response}")
                
        except Exception as e:
            self.result_text.setText(f"Error during submission: {str(e)}")

def PLUGIN_ENTRY():
    return HashDBLookup() 