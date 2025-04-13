# Windows PE File Analyzer with Malware Detection for Google Colab
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import hashlib
import os
import time
from datetime import datetime
import seaborn as sns
from pathlib import Path
from IPython.display import display, HTML
import ipywidgets as widgets
from IPython.display import clear_output
from google.colab import files
import joblib

# Install LIEF library if not already installed
!pip install -q lief scikit-learn yara-python

import lief
import math
import re
import string
from collections import Counter
import sys

# Create necessary directories
os.makedirs("/content/uploads", exist_ok=True)
os.makedirs("/content/reports", exist_ok=True)
os.makedirs("/content/models", exist_ok=True)

# PE Feature Extractor implementation with improved detection capabilities
class PEFeatureExtractor:
    """Extract features from PE files with improved malware detection."""
    
    def __init__(self):
        self.features_list = []
        self.string_regex = re.compile(b'[ -~]{5,}')  # Printable strings of length >= 5
        self.url_regex = re.compile(b'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+')
        self.registry_regex = re.compile(b'HKEY_|HKLM|HKCU|HKCR|HKU')
        self.path_regex = re.compile(b'[a-zA-Z]:\\\\(?:[^\\\\/:*?"<>|\r\n]+\\\\)*[^\\\\/:*?"<>|\r\n]*')
        
        # Known suspicious API calls related to malware behaviors
        self.suspicious_api_calls = [
            b'VirtualAlloc', b'VirtualProtect', b'CreateProcess', b'CreateRemoteThread',
            b'ReadProcessMemory', b'WriteProcessMemory', b'SetWindowsHook', b'GetProcAddress',
            b'LoadLibrary', b'ShellExecute', b'WinExec', b'WSASocket', b'connect', b'InternetOpen',
            b'InternetConnect', b'HttpSendRequest', b'RegCreateKey', b'RegSetValue',
            b'CreateService', b'StartService', b'QueryPerformanceCounter', b'IsDebuggerPresent',
            b'Sleep', b'SetFileTime', b'FindWindow', b'EnumWindows', b'CreateMutex',
            b'CryptEncrypt', b'CryptDecrypt', b'CryptGenKey', b'MapViewOfFile'
        ]
        
        # Packer/obfuscator patterns
        self.packer_signatures = [
            b'UPX', b'ASPack', b'PECompact', b'Themida', b'Enigma', b'VMProtect', 
            b'Obsidium', b'FSG', b'NSIS', b'MPRESS'
        ]
        
        # Anti-analysis patterns
        self.anti_analysis_patterns = [
            b'IsDebuggerPresent', b'CheckRemoteDebuggerPresent', b'OutputDebugString',
            b'GetTickCount', b'QueryPerformanceCounter', b'GetSystemTime',
            b'VirtualBox', b'VMware', b'QEMU', b'SbieDll', b'Sandbox', b'WinDbg'
        ]
    
    def raw_features(self, raw_data):
        """Extract raw features from PE file data with improved detection"""
        features = {}
        
        # Basic check for PE file
        if raw_data[:2] == b'MZ':
            try:
                # Parse with LIEF
                pe = lief.parse(raw_data)
                if not pe:
                    return self._get_fallback_features(raw_data)
                
                # General features
                general = {
                    "size": len(raw_data),
                    "vsize": sum(section.virtual_size for section in pe.sections),
                    "has_debug": int(len(pe.debug) > 0),
                    "exports": len(pe.exported_functions),
                    "imports": len(list(pe.imports)),
                    "has_relocations": int(pe.has_relocations),
                    "has_resources": int(pe.has_resources),
                    "has_signature": int(pe.has_signature),
                    "has_tls": int(pe.has_tls),
                    "symbols": len(pe.symbols),
                }
                
                # Calculate entropy
                entire_file_entropy = self._calculate_entropy(raw_data)
                general["entropy"] = entire_file_entropy
                
                # Check for packer detection
                general["packer_detected"] = self._check_for_packers(raw_data)
                
                # Check for anti-analysis techniques
                general["anti_analysis_detected"] = self._check_for_anti_analysis(raw_data)
                
                # Section features
                sections = []
                section_entropy_list = []
                for section in pe.sections:
                    try:
                        section_data = pe.get_content_from_virtual_address(
                            section.virtual_address, section.virtual_size
                        )
                        if section_data:
                            section_entropy = self._calculate_entropy(section_data)
                            section_entropy_list.append(section_entropy)
                        else:
                            section_entropy = 0
                    except:
                        section_entropy = 0
                    
                    section_info = {
                        "name": section.name,
                        "size": section.size,
                        "entropy": section_entropy,
                        "vsize": section.virtual_size,
                        "props": [],
                    }
                    
                    # Section characteristics
                    if section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_READ):
                        section_info["props"].append("MEM_READ")
                    if section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_WRITE):
                        section_info["props"].append("MEM_WRITE")
                    if section.has_characteristic(lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE):
                        section_info["props"].append("MEM_EXECUTE")
                    
                    sections.append(section_info)
                
                general["section_entropy_mean"] = np.mean(section_entropy_list) if section_entropy_list else 0
                general["section_entropy_max"] = np.max(section_entropy_list) if section_entropy_list else 0
                general["section_entropy_min"] = np.min(section_entropy_list) if section_entropy_list else 0
                
                # Suspicious section names (common in malware)
                suspicious_section_names = ['.rsrc', '.data', '.text', '.rdata', '.reloc']
                custom_sections = [s for s in sections if s["name"] not in suspicious_section_names]
                general["custom_sections"] = len(custom_sections)
                
                # String features with enhanced detection
                strings_result = self._extract_strings(raw_data)
                
                # Import features with suspicious API detection
                imports = {}
                suspicious_imports_count = 0
                
                for imp in pe.imports:
                    imports[imp.name.lower()] = len(imp.entries)
                    
                    # Check for suspicious APIs in this import
                    for entry in imp.entries:
                        if entry.name:
                            name_bytes = entry.name.encode('utf-8', errors='ignore')
                            if any(api in name_bytes for api in self.suspicious_api_calls):
                                suspicious_imports_count += 1
                
                general["suspicious_imports"] = suspicious_imports_count
                general["has_many_imports"] = int(len(list(pe.imports)) > 50)  # Suspicious if many imports
                
                # Check for small import count (could be packed/encrypted)
                general["few_imports"] = int(len(list(pe.imports)) < 5 and len(raw_data) > 20000)
                
                # Header features
                header = {}
                if pe.has_rich_header:
                    header["rich_header"] = True
                
                try:
                    header["dos_header"] = {
                        "magic": pe.dos_header.magic,
                        "used_bytes_in_the_last_page": pe.dos_header.used_bytes_in_the_last_page,
                        "file_size_in_pages": pe.dos_header.file_size_in_pages,
                    }
                except:
                    header["dos_header"] = {}
                
                # Check for abnormal entry point
                if pe.has_entrypoint:
                    header["entrypoint"] = pe.entrypoint
                    
                    # Find the section containing the entry point
                    ep_section = None
                    for section in pe.sections:
                        if (section.virtual_address <= pe.entrypoint < 
                            section.virtual_address + section.virtual_size):
                            ep_section = section
                            break
                    
                    if ep_section:
                        header["ep_section"] = ep_section.name
                        # Entry point in unusual section (not .text) is suspicious
                        header["unusual_ep_section"] = int(ep_section.name != ".text")
                
                features = {
                    "general": general,
                    "section": {"sections": sections},
                    "strings": strings_result,
                    "imports": imports,
                    "header": header,
                }
                
                return features
                
            except Exception as e:
                print(f"Error parsing PE file: {e}")
                return self._get_fallback_features(raw_data)
        else:
            return self._get_fallback_features(raw_data)
    
    def _get_fallback_features(self, raw_data):
        """Fallback features when PE parsing fails"""
        strings_result = self._extract_strings(raw_data)
        entropy = self._calculate_entropy(raw_data)
        
        # Check for signs of obfuscation in raw data
        packer_detected = self._check_for_packers(raw_data)
        anti_analysis_detected = self._check_for_anti_analysis(raw_data)
        
        return {
            "general": {
                "size": len(raw_data),
                "entropy": entropy,
                "imports": 0,
                "exports": 0,
                "has_debug": 0,
                "has_relocations": 0,
                "has_resources": 0,
                "has_signature": 0,
                "has_tls": 0,
                "packer_detected": packer_detected,
                "anti_analysis_detected": anti_analysis_detected,
                "section_entropy_mean": entropy,
                "section_entropy_max": entropy,
                "section_entropy_min": entropy,
                "suspicious_imports": 0,
                "has_many_imports": 0,
                "few_imports": 0,
                "custom_sections": 0,
            },
            "strings": strings_result,
            "section": {"sections": []},
            "imports": {},
            "header": {},
        }
    
    def _check_for_packers(self, data):
        """Check for common packer signatures in binary data"""
        return int(any(sig in data for sig in self.packer_signatures))
    
    def _check_for_anti_analysis(self, data):
        """Check for anti-debugging and anti-VM techniques"""
        return int(any(pattern in data for pattern in self.anti_analysis_patterns))
    
    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        byte_counts = Counter(data)
        total_bytes = len(data)
        entropy = 0
        
        for count in byte_counts.values():
            probability = count / total_bytes
            entropy -= probability * math.log2(probability)
            
        return entropy
    
    def _extract_strings(self, data):
        """Extract strings from binary data with improved analysis"""
        # Find all strings
        strings = self.string_regex.findall(data)
        
        # Find URLs, registry keys, and file paths
        urls = self.url_regex.findall(data)
        registry = self.registry_regex.findall(data)
        paths = self.path_regex.findall(data)
        
        # Look for suspicious strings common in malware
        suspicious_strings = [
            b'cmd.exe', b'powershell', b'wscript', b'regsvr32', b'rundll32',
            b'temp', b'tmp', b'http', b'tcp', b'udp', b'password', b'login',
            b'admin', b'crypt', b'hidden', b'bitcoin', b'ransom'
        ]
        
        suspicious_string_count = sum(1 for s in strings if any(sus in s.lower() for sus in suspicious_strings))
        
        # Compute string entropy
        string_concat = b''.join(strings)
        string_entropy = self._calculate_entropy(string_concat) if string_concat else 0
        
        # Check for command line arguments
        has_cmd_args = int(any(b'-' in s or b'/' in s for s in strings))
        
        # Check for base64 encoded strings (common in obfuscated malware)
        b64_pattern = re.compile(b'[A-Za-z0-9+/=]{20,}')
        b64_strings = b64_pattern.findall(data)
        
        # Check for long encrypted/encoded strings
        long_strings = [s for s in strings if len(s) > 50]
        has_long_strings = int(len(long_strings) > 0)
        
        # Check for PDB paths (legitimate software often has these)
        pdb_paths = [s for s in strings if b'.pdb' in s]
        has_pdb = int(len(pdb_paths) > 0)
        
        return {
            "numstrings": len(strings),
            "avlength": np.mean([len(s) for s in strings]) if strings else 0,
            "urls": len(urls),
            "registry": len(registry),
            "paths": len(paths),
            "entropy": string_entropy,
            "printables": len(string_concat) if string_concat else 0,
            "suspicious_string_count": suspicious_string_count,
            "has_cmd_args": has_cmd_args,
            "b64_strings": len(b64_strings),
            "has_long_strings": has_long_strings,
            "has_pdb": has_pdb,
        }
    
    def process_raw_features(self, raw_features):
        """Process raw features into a vector for ML with improved detection"""
        # Converting features to numpy array with better normalization
        feature_vector = np.zeros(128)  # Using a fixed size feature vector
        
        idx = 0
        
        # Add general features
        if "general" in raw_features:
            general = raw_features["general"]
            
            # Basic PE properties
            feature_vector[idx] = np.log1p(general.get("size", 0)) / 20.0  # Better size normalization with log
            idx += 1
            feature_vector[idx] = general.get("entropy", 0) / 8.0  # Normalize entropy
            idx += 1
            feature_vector[idx] = np.log1p(general.get("imports", 0)) / 10.0  # Better imports normalization with log
            idx += 1
            feature_vector[idx] = np.log1p(general.get("exports", 0)) / 10.0  # Better exports normalization with log
            idx += 1
            
            # PE file characteristics
            feature_vector[idx] = general.get("has_debug", 0)
            idx += 1
            feature_vector[idx] = general.get("has_relocations", 0)
            idx += 1
            feature_vector[idx] = general.get("has_resources", 0)
            idx += 1
            feature_vector[idx] = general.get("has_signature", 0)
            idx += 1
            feature_vector[idx] = general.get("has_tls", 0)
            idx += 1
            
            # Advanced malware indicators
            feature_vector[idx] = general.get("packer_detected", 0)
            idx += 1
            feature_vector[idx] = general.get("anti_analysis_detected", 0)
            idx += 1
            feature_vector[idx] = np.tanh(general.get("suspicious_imports", 0) / 10.0)  # Scaled using tanh
            idx += 1
            feature_vector[idx] = general.get("has_many_imports", 0)
            idx += 1
            feature_vector[idx] = general.get("few_imports", 0)
            idx += 1
            feature_vector[idx] = np.log1p(general.get("custom_sections", 0))
            idx += 1
            
            # Section entropy features
            feature_vector[idx] = general.get("section_entropy_mean", 0) / 8.0
            idx += 1
            feature_vector[idx] = general.get("section_entropy_max", 0) / 8.0
            idx += 1
            feature_vector[idx] = general.get("section_entropy_min", 0) / 8.0
            idx += 1
        
        # Add string features - enhanced for better malware detection
        if "strings" in raw_features:
            strings = raw_features["strings"]
            feature_vector[idx] = np.log1p(strings.get("numstrings", 0)) / 10.0  # Better normalization
            idx += 1
            feature_vector[idx] = strings.get("avlength", 0) / 100.0  # Normalize average string length
            idx += 1
            feature_vector[idx] = np.tanh(strings.get("urls", 0) / 5.0)  # Better URL normalization with tanh
            idx += 1
            feature_vector[idx] = np.tanh(strings.get("registry", 0) / 5.0)  # Better registry normalization
            idx += 1
            feature_vector[idx] = np.tanh(strings.get("paths", 0) / 10.0)  # Better paths normalization
            idx += 1
            feature_vector[idx] = strings.get("entropy", 0) / 8.0  # Normalize string entropy
            idx += 1
            
            # Additional string-based features for better malware detection
            feature_vector[idx] = np.tanh(strings.get("suspicious_string_count", 0) / 10.0)
            idx += 1
            feature_vector[idx] = strings.get("has_cmd_args", 0)
            idx += 1
            feature_vector[idx] = np.tanh(strings.get("b64_strings", 0) / 5.0)
            idx += 1
            feature_vector[idx] = strings.get("has_long_strings", 0)
            idx += 1
            feature_vector[idx] = strings.get("has_pdb", 0)  # Legitimate software often has PDB paths
            idx += 1
        
        # Add section features with enhanced detection
        if "section" in raw_features and "sections" in raw_features["section"]:
            sections = raw_features["section"]["sections"]
            feature_vector[idx] = np.log1p(len(sections))  # Number of sections (log-scaled)
            idx += 1
            
            # Count sections with specific characteristics
            executable_sections = sum(1 for s in sections if "MEM_EXECUTE" in s.get("props", []))
            feature_vector[idx] = executable_sections  # Number of executable sections
            idx += 1
            
            writable_executable_sections = sum(1 for s in sections if "MEM_EXECUTE" in s.get("props", []) 
                                             and "MEM_WRITE" in s.get("props", []))
            feature_vector[idx] = writable_executable_sections  # Number of RWX sections (very suspicious)
            idx += 1
            
            suspicious_sections = sum(1 for s in sections if s.get("entropy", 0) > 7.0)
            feature_vector[idx] = suspicious_sections  # Number of high entropy sections
            idx += 1
            
            # Check section size vs virtual size discrepancy (common in packed malware)
            size_discrepancies = sum(1 for s in sections if s.get("vsize", 0) > 10 * s.get("size", 1))
            feature_vector[idx] = size_discrepancies
            idx += 1
            
            # Check for unusual section names
            common_section_names = [".text", ".data", ".rdata", ".rsrc", ".reloc", ".idata"]
            unusual_sections = sum(1 for s in sections if s.get("name") not in common_section_names)
            feature_vector[idx] = unusual_sections
            idx += 1
        
        # Header features
        if "header" in raw_features:
            header = raw_features["header"]
            
            # Rich header presence (can be an indicator)
            feature_vector[idx] = int(header.get("rich_header", False))
            idx += 1
            
            # Unusual entry point section
            feature_vector[idx] = header.get("unusual_ep_section", 0)
            idx += 1
        
        # Import features
        if "imports" in raw_features:
            imports = raw_features["imports"]
            
            # Check for networking capabilities
            networking_apis = ["ws2_32.dll", "wininet.dll", "wsock32.dll", "urlmon.dll"]
            feature_vector[idx] = int(any(api in imports for api in networking_apis))
            idx += 1
            
            # Check for crypto capabilities
            crypto_apis = ["advapi32.dll", "crypt32.dll", "cryptsp.dll"]
            feature_vector[idx] = int(any(api in imports for api in crypto_apis))
            idx += 1
            
            # Check for process manipulation
            process_apis = ["kernel32.dll", "ntdll.dll"]
            feature_vector[idx] = int(any(api in imports for api in process_apis))
            idx += 1
        
        return feature_vector

# Function to load a custom trained model
def load_custom_model():
    """Upload and load a custom trained model"""
    print("Please upload your trained model file (.pkl or similar):")
    uploaded = files.upload()
    
    if not uploaded:
        print("No model file was uploaded. Using heuristic-based detection only.")
        return None
    
    model_filename = list(uploaded.keys())[0]
    model_path = f"/content/models/{model_filename}"
    
    try:
        with open(model_path, "wb") as f:
            f.write(uploaded[model_filename])
        
        print(f"Loading model from {model_path}...")
        model = joblib.load(model_path)
        print("Model loaded successfully!")
        return model
    except Exception as e:
        print(f"Error loading model: {e}")
        print("Using heuristic-based detection only")
        return None

# Initialize PE Feature Extractor
pe_extractor = PEFeatureExtractor()

# Function to extract features from a file
def extract_file_features(file_path):
    """Extract features from a file for malware prediction using enhanced features"""
    features = {}
    try:
        # Basic file info
        file_size = os.path.getsize(file_path)
        file_name = os.path.basename(file_path)

        # Read file bytes
        with open(file_path, "rb") as f:
            data = f.read()

        # Calculate basic hashes
        md5_hash = hashlib.md5(data).hexdigest()
        sha256_hash = hashlib.sha256(data).hexdigest()

        # Extract features
        ember_features = pe_extractor.raw_features(data)
        processed_features = pe_extractor.process_raw_features(ember_features)

        # Basic features
        features = {
            "file_name": file_name,
            "file_size": file_size,
            "md5": md5_hash,
            "sha256": sha256_hash,
            "timestamp": datetime.fromtimestamp(
                os.path.getctime(file_path)
            ).isoformat(),
        }

        # For simple PE detection
        is_pe = data[:2] == b"MZ"
        features["is_pe"] = is_pe

        # Extract ML features
        ml_features = {}

        if "general" in ember_features:
            general_info = ember_features["general"]
            ml_features.update(
                {
                    "file_size": file_size,
                    "is_packed": int(general_info.get("entropy", 0) > 7.0 or 
                                   general_info.get("packer_detected", 0) == 1),
                    "has_debug": general_info.get("has_debug", 0),
                    "has_relocations": general_info.get("has_relocations", 0),
                    "has_resources": general_info.get("has_resources", 0),
                    "has_signature": general_info.get("has_signature", 0),
                    "has_tls": general_info.get("has_tls", 0),
                    "num_imports": general_info.get("imports", 0),
                    "num_exports": general_info.get("exports", 0),
                    "packer_detected": general_info.get("packer_detected", 0),
                    "anti_analysis_detected": general_info.get("anti_analysis_detected", 0),
                    "suspicious_imports": general_info.get("suspicious_imports", 0),
                    "few_imports": general_info.get("few_imports", 0),
                    "has_many_imports": general_info.get("has_many_imports", 0),
                    "entropy": general_info.get("entropy", 0),
                    "section_entropy_mean": general_info.get("section_entropy_mean", 0),
                    "section_entropy_max": general_info.get("section_entropy_max", 0),
                }
            )

        # Add string features
        if "strings" in ember_features:
            strings_info = ember_features["strings"]
            ml_features.update(
                {
                    "num_strings": strings_info.get("numstrings", 0),
                    "avg_string_length": strings_info.get("avlength", 0),
                    "num_paths": strings_info.get("paths", 0),
                    "num_urls": strings_info.get("urls", 0),
                    "num_registry": strings_info.get("registry", 0),
                    "has_pdb": int(b".pdb" in data),
                    "string_entropy": strings_info.get("entropy", 0),
                    "suspicious_string_count": strings_info.get("suspicious_string_count", 0),
                    "has_cmd_args": strings_info.get("has_cmd_args", 0),
                    "b64_strings": strings_info.get("b64_strings", 0),
                    "has_long_strings": strings_info.get("has_long_strings", 0),
                }
            )

        # Add section features
        if "section" in ember_features:
            section_info = ember_features["section"]
            if isinstance(section_info, dict) and "sections" in section_info:
                sections = section_info["sections"]
                num_sections = len(sections)
                suspicious_sections = sum(
                    1 for s in sections if s.get("entropy", 0) > 7.0
                )
                executable_sections = sum(
                    1 for s in sections if "MEM_EXECUTE" in s.get("props", [])
                )
                writable_executable_sections = sum(
                    1 for s in sections if "MEM_EXECUTE" in s.get("props", []) 
                    and "MEM_WRITE" in s.get("props", [])
                )
                
                # Check for suspicious section size (virtual vs physical)
                size_discrepancies = sum(
                    1 for s in sections if s.get("vsize", 0) > 10 * s.get("size", 1)
                )

                ml_features.update(
                    {
                        "num_sections": num_sections,
                        "num_suspicious_sections": suspicious_sections,
                        "num_executable_sections": executable_sections,
                        "num_rwx_sections": writable_executable_sections,
                        "section_size_discrepancies": size_discrepancies,
                    }
                )
        
        # Add header features
        if "header" in ember_features:
            header_info = ember_features["header"]
            ml_features.update({
                "has_rich_header": int(header_info.get("rich_header", False)),
                "unusual_ep_section": header_info.get("unusual_ep_section", 0),
            })

        # Calculate advanced threat score with more weights for Malware Bazaar samples
        threat_score = 0
        
        # Size-based scoring
        if file_size < 30000:  # Very small executables are suspicious
            threat_score += 2
        elif file_size > 5000000:  # Very large executables can be suspicious
            threat_score += 1
        
        # Packing/obfuscation indicators (critical for Malware Bazaar samples)
        if ml_features.get("is_packed", 0) == 1:
            threat_score += 5
        if ml_features.get("packer_detected", 0) == 1:
            threat_score += 4
        if ml_features.get("entropy", 0) > 6.5:  # Lower the threshold
            threat_score += 3
        if ml_features.get("section_entropy_max", 0) > 7.2:
            threat_score += 3
        
        # Anti-analysis techniques (very common in Malware Bazaar samples)
        if ml_features.get("anti_analysis_detected", 0) == 1:
            threat_score += 5
        
        # Suspicious sections (common in malware)
        if ml_features.get("num_suspicious_sections", 0) > 0:
            threat_score += ml_features.get("num_suspicious_sections", 0) * 2
        if ml_features.get("section_size_discrepancies", 0) > 0:
            threat_score += ml_features.get("section_size_discrepancies", 0) * 2
        if ml_features.get("num_rwx_sections", 0) > 0:
            threat_score += ml_features.get("num_rwx_sections", 0) * 3
        
        # Unusual entry point section (common in malware)
        if ml_features.get("unusual_ep_section", 0) == 1:
            threat_score += 3
        
        # Suspicious imports (common in malware)
        if ml_features.get("suspicious_imports", 0) > 5:
            threat_score += 4
        elif ml_features.get("suspicious_imports", 0) > 0:
            threat_score += 2
        
        # Few imports but large file (likely packed/obfuscated)
        if ml_features.get("few_imports", 0) == 1:
            threat_score += 3
        
        # Suspicious strings
        # Suspicious strings 
        if ml_features.get("suspicious_string_count", 0) > 10:
            threat_score += 4
        elif ml_features.get("suspicious_string_count", 0) > 5:
            threat_score += 2
        
        # Base64 encoded strings (common in obfuscated malware)
        if ml_features.get("b64_strings", 0) > 5:
            threat_score += 3
        
        # No PDB path (legitimate software often has these)
        if ml_features.get("has_pdb", 0) == 0:
            threat_score += 1
        
        # Presence of signature (legitimate software often has these)
        if ml_features.get("has_signature", 0) == 1:
            threat_score -= 3  # Reduce score if signed
        
        # Legitimate software often has debug info
        if ml_features.get("has_debug", 0) == 1:
            threat_score -= 2
        
        # Assign threat level based on score
        threat_level = "Unknown"
        if threat_score < 0:
            threat_level = "Clean"
        elif threat_score < 5:
            threat_level = "Likely Clean"
        elif threat_score < 10:
            threat_level = "Suspicious"
        elif threat_score < 15:
            threat_level = "Highly Suspicious"
        else:
            threat_level = "Likely Malicious"
        
        # Add ML features and threat assessment to results
        features["ml_features"] = ml_features
        features["processed_features"] = processed_features.tolist()
        features["threat_score"] = threat_score
        features["threat_level"] = threat_level
        
        return features
    except Exception as e:
        print(f"Error extracting features: {e}")
        return {
            "file_name": os.path.basename(file_path),
            "error": str(e),
            "threat_level": "Analysis Failed"
        }

# YARA rule scanning for additional pattern-based detection
def create_default_yara_rules():
    """Create default YARA rules for common malware patterns"""
    import yara
    
    default_rules = """
    rule PossibleRansomware {
        meta:
            description = "Detects potential ransomware indicators"
            severity = "high"
        strings:
            $ransom_note1 = "ransom" nocase
            $ransom_note2 = "bitcoin" nocase
            $ransom_note3 = "decrypt" nocase
            $ransom_note4 = "encrypted your files" nocase
            $ransom_note5 = "pay" nocase
            $ransom_note6 = "restore" nocase
            $file_ext1 = ".locked" nocase
            $file_ext2 = ".encrypted" nocase
            $file_ext3 = ".crypted" nocase
        condition:
            3 of ($ransom_note*) or any of ($file_ext*)
    }
    
    rule SuspiciousAPIUsage {
        meta:
            description = "Detects suspicious API usage common in malware"
            severity = "medium"
        strings:
            $process_injection1 = "VirtualAlloc" nocase
            $process_injection2 = "WriteProcessMemory" nocase
            $process_injection3 = "CreateRemoteThread" nocase
            $process_injection4 = "NtCreateThreadEx" nocase
            $evasion1 = "IsDebuggerPresent" nocase
            $evasion2 = "CheckRemoteDebuggerPresent" nocase
            $evasion3 = "GetTickCount" nocase
            $evasion4 = "QueryPerformanceCounter" nocase
            $vm_detect1 = "VirtualBox" nocase
            $vm_detect2 = "VMware" nocase
            $vm_detect3 = "QEMU" nocase
            $vm_detect4 = "SbieDll" nocase
        condition:
            3 of ($process_injection*) or 3 of ($evasion*) or 2 of ($vm_detect*)
    }
    
    rule KnownPacker {
        meta:
            description = "Detects known packer signatures"
            severity = "medium"
        strings:
            $upx = "UPX" nocase
            $aspack = "ASPack" nocase
            $pecompact = "PECompact" nocase
            $themida = "Themida" nocase
            $enigma = "Enigma" nocase
            $vmprotect = "VMProtect" nocase
            $obsidium = "Obsidium" nocase
        condition:
            any of them
    }
    
    rule SuspiciousShellCommands {
        meta:
            description = "Detects suspicious shell commands often used by malware"
            severity = "high"
        strings:
            $cmd1 = "cmd.exe" nocase
            $cmd2 = "powershell" nocase
            $cmd3 = "reg" nocase
            $cmd4 = "sc" nocase
            $cmd5 = "netsh" nocase
            $cmd6 = "schtasks" nocase
            $cmd7 = "wmic" nocase
            $cmd8 = "bitsadmin" nocase
            $cmd9 = "regsvr32" nocase
            $cmd10 = "rundll32" nocase
        condition:
            3 of them
    }
    
    rule NetworkingCapabilities {
        meta:
            description = "Detects network communication capabilities"
            severity = "medium"
        strings:
            $net1 = "WinInet" nocase
            $net2 = "InternetConnect" nocase
            $net3 = "HttpSendRequest" nocase
            $net4 = "URLDownloadToFile" nocase
            $net5 = "WSASocket" nocase
            $net6 = "connect" nocase
            $net7 = "send" nocase
            $net8 = "recv" nocase
            $net9 = "socket" nocase
        condition:
            3 of them
    }
    
    rule Base64EncodedPE {
        meta:
            description = "Detects Base64 encoded PE files"
            severity = "high"
        strings:
            $b64_mz = "TVo" // Base64 encoding of "MZ"
            $b64_pe = "UEU" // Base64 encoding of "PE"
        condition:
            $b64_mz and $b64_pe
    }
    """
    
    try:
        with open("/content/default_rules.yar", "w") as f:
            f.write(default_rules)
        
        rules = yara.compile(filepath="/content/default_rules.yar")
        return rules
    except Exception as e:
        print(f"Error creating YARA rules: {e}")
        return None

# Function to upload and scan a PE file
def upload_and_analyze():
    """Analyze a PE file for potential malware"""
    import yara
    print("\nAnalyzing file: smallexe.exe")
    
    try:
        file_path = "smallexe.exe"
        
        # Load custom model if provided, otherwise use heuristic detection
        custom_model = None
        stacked_model_path = "stacked_model.pkl"  # Look for model in current directory
        
        if os.path.exists(stacked_model_path):
            try:
                custom_model = joblib.load(stacked_model_path)
                print("Loaded pre-trained model from stacked_model.pkl")
            except Exception as e:
                print(f"Error loading pre-trained model: {e}")
        
        # Create default YARA rules
        yara_rules = create_default_yara_rules()
        
        start_time = time.time()
        print(f"Analyzing file...")
        
        # Extract features
        features = extract_file_features(file_path)
        
        # ML prediction if model is available
        if custom_model is not None and "processed_features" in features:
            try:
                features_array = np.array(features["processed_features"]).reshape(1, -1)
                ml_prediction = custom_model.predict_proba(features_array)[0]
                
                # Get the predicted class and probability
                predicted_class = custom_model.classes_[np.argmax(ml_prediction)]
                prediction_prob = np.max(ml_prediction)
                
                features["ml_prediction"] = {
                    "class": int(predicted_class),
                    "probability": float(prediction_prob),
                    "label": "Malicious" if predicted_class == 1 else "Benign"
                }
                
                # Adjust threat level based on ML prediction
                if predicted_class == 1 and prediction_prob > 0.8:
                    features["threat_level"] = "Likely Malicious (ML)"
                elif predicted_class == 1 and prediction_prob > 0.6:
                    features["threat_level"] = "Highly Suspicious (ML)"
                elif predicted_class == 0 and prediction_prob > 0.8:
                    if features["threat_score"] < 10:  # If heuristics aren't strongly malicious
                        features["threat_level"] = "Likely Clean (ML)"
            except Exception as e:
                print(f"Error during ML prediction: {e}")
        
        # YARA scanning
        if yara_rules is not None:
            try:
                with open(file_path, "rb") as f:
                    file_data = f.read()
                
                yara_matches = yara_rules.match(data=file_data)
                
                if yara_matches:
                    features["yara_matches"] = []
                    for match in yara_matches:
                        features["yara_matches"].append({
                            "rule": match.rule,
                            "meta": match.meta,
                            "strings": [(s[1], s[0], s[2]) for s in match.strings],
                        })
                    
                    # Adjust threat level based on YARA matches
                    high_severity_matches = sum(1 for match in yara_matches if match.meta.get("severity") == "high")
                    
                    if high_severity_matches > 0 and features["threat_level"] not in ["Likely Malicious", "Likely Malicious (ML)"]:
                        features["threat_level"] = "Highly Suspicious (YARA)"
            except Exception as e:
                print(f"Error during YARA scanning: {e}")
        
        end_time = time.time()
        analysis_time = end_time - start_time
        features["analysis_time"] = analysis_time
        
        # Save the analysis report
        report_filename = f"{os.path.splitext(os.path.basename(file_path))[0]}_report.json"
        report_path = f"{report_filename}"
        
        with open(report_path, "w") as f:
            import json
            json.dump(features, f, indent=4)
        
        print(f"Analysis completed in {analysis_time:.2f} seconds")
        print(f"Report saved to {report_path}")
        
        # Display summary report
        display_analysis_summary(features)
        
        return features
    except Exception as e:
        print(f"Error analyzing file: {e}")
        raise

# Function to display analysis summary
def display_analysis_summary(features):
    """Display a summary of the analysis results with visualizations"""
    if "error" in features:
        print(f"Error: {features['error']}")
        return
    
    # Create a formatted HTML report
    html_report = f"""
    <h2>PE File Analysis Summary</h2>
    <table style="width:100%; border-collapse: collapse;">
        <tr style="background-color: #f2f2f2;">
            <th style="text-align: left; padding: 8px; border: 1px solid #ddd;">Property</th>
            <th style="text-align: left; padding: 8px; border: 1px solid #ddd;">Value</th>
        </tr>
        <tr>
            <td style="padding: 8px; border: 1px solid #ddd;">File Name</td>
            <td style="padding: 8px; border: 1px solid #ddd;">{features['file_name']}</td>
        </tr>
        <tr>
            <td style="padding: 8px; border: 1px solid #ddd;">File Size</td>
            <td style="padding: 8px; border: 1px solid #ddd;">{features['file_size']} bytes ({features['file_size']/1024:.2f} KB)</td>
        </tr>
        <tr>
            <td style="padding: 8px; border: 1px solid #ddd;">MD5</td>
            <td style="padding: 8px; border: 1px solid #ddd;">{features['md5']}</td>
        </tr>
        <tr>
            <td style="padding: 8px; border: 1px solid #ddd;">SHA256</td>
            <td style="padding: 8px; border: 1px solid #ddd;">{features['sha256']}</td>
        </tr>
        <tr>
            <td style="padding: 8px; border: 1px solid #ddd;">Is PE File</td>
            <td style="padding: 8px; border: 1px solid #ddd;">{"Yes" if features['is_pe'] else "No"}</td>
        </tr>
        <tr>
            <td style="padding: 8px; border: 1px solid #ddd;">Threat Score</td>
            <td style="padding: 8px; border: 1px solid #ddd;">{features.get('threat_score', 'N/A')}</td>
        </tr>
        <tr>
            <td style="padding: 8px; border: 1px solid #ddd;">Threat Level</td>
            <td style="padding: 8px; border: 1px solid #ddd; font-weight: bold; color: {
                'green' if features['threat_level'] in ['Clean', 'Likely Clean', 'Likely Clean (ML)'] 
                else 'orange' if features['threat_level'] in ['Suspicious'] 
                else 'red' if features['threat_level'] in ['Highly Suspicious', 'Highly Suspicious (YARA)', 'Highly Suspicious (ML)', 'Likely Malicious', 'Likely Malicious (ML)'] 
                else 'black'
            };">{features['threat_level']}</td>
        </tr>
        <tr>
            <td style="padding: 8px; border: 1px solid #ddd;">Analysis Time</td>
            <td style="padding: 8px; border: 1px solid #ddd;">{features.get('analysis_time', 0):.2f} seconds</td>
        </tr>
    </table>
    """
    
    # Add ML prediction if available
    if "ml_prediction" in features:
        ml_pred = features["ml_prediction"]
        html_report += f"""
        <h3>Machine Learning Analysis</h3>
        <table style="width:100%; border-collapse: collapse;">
            <tr style="background-color: #f2f2f2;">
                <th style="text-align: left; padding: 8px; border: 1px solid #ddd;">Prediction</th>
                <th style="text-align: left; padding: 8px; border: 1px solid #ddd;">Confidence</th>
            </tr>
            <tr>
                <td style="padding: 8px; border: 1px solid #ddd; color: {'red' if ml_pred['label'] == 'Malicious' else 'green'};">{ml_pred['label']}</td>
                <td style="padding: 8px; border: 1px solid #ddd;">{ml_pred['probability']:.2%}</td>
            </tr>
        </table>
        """
    
    # Add YARA matches if available
    if "yara_matches" in features and features["yara_matches"]:
        html_report += f"""
        <h3>YARA Matches</h3>
        <table style="width:100%; border-collapse: collapse;">
            <tr style="background-color: #f2f2f2;">
                <th style="text-align: left; padding: 8px; border: 1px solid #ddd;">Rule</th>
                <th style="text-align: left; padding: 8px; border: 1px solid #ddd;">Severity</th>
                <th style="text-align: left; padding: 8px; border: 1px solid #ddd;">Description</th>
            </tr>
        """
        
        for match in features["yara_matches"]:
            html_report += f"""
            <tr>
                <td style="padding: 8px; border: 1px solid #ddd;">{match['rule']}</td>
                <td style="padding: 8px; border: 1px solid #ddd; color: {
                    'red' if match['meta'].get('severity') == 'high' 
                    else 'orange' if match['meta'].get('severity') == 'medium' 
                    else 'black'
                };">{match['meta'].get('severity', 'unknown')}</td>
                <td style="padding: 8px; border: 1px solid #ddd;">{match['meta'].get('description', 'No description')}</td>
            </tr>
            """
        
        html_report += "</table>"
    
    # Add key indicators if available
    if "ml_features" in features:
        ml_features = features["ml_features"]
        
        # Indicators to highlight
        key_indicators = []
        
        if ml_features.get("is_packed", 0) == 1:
            key_indicators.append(("Packed/Obfuscated", "High", "File appears to be packed or obfuscated"))
        
        if ml_features.get("packer_detected", 0) == 1:
            key_indicators.append(("Packer Detected", "High", "Known packer signatures detected"))
        
        if ml_features.get("anti_analysis_detected", 0) == 1:
            key_indicators.append(("Anti-Analysis", "High", "Anti-debugging or VM detection techniques found"))
        
        if ml_features.get("suspicious_imports", 0) > 5:
            key_indicators.append(("Suspicious APIs", "High", f"{ml_features.get('suspicious_imports', 0)} suspicious API imports detected"))
        
        if ml_features.get("num_rwx_sections", 0) > 0:
            key_indicators.append(("RWX Sections", "High", f"{ml_features.get('num_rwx_sections', 0)} sections with read/write/execute permissions"))
        
        if ml_features.get("suspicious_string_count", 0) > 5:
            key_indicators.append(("Suspicious Strings", "Medium", f"{ml_features.get('suspicious_string_count', 0)} suspicious strings detected"))
        
        if ml_features.get("b64_strings", 0) > 5:
            key_indicators.append(("Base64 Strings", "Medium", f"{ml_features.get('b64_strings', 0)} potential Base64 encoded strings"))
        
        if ml_features.get("entropy", 0) > 7.0:
            key_indicators.append(("High Entropy", "Medium", f"File entropy: {ml_features.get('entropy', 0):.2f}"))
        
        if ml_features.get("unusual_ep_section", 0) == 1:
            key_indicators.append(("Unusual Entry Point", "Medium", "Entry point not in .text section"))
        
        if key_indicators:
            html_report += f"""
            <h3>Key Indicators</h3>
            <table style="width:100%; border-collapse: collapse;">
                <tr style="background-color: #f2f2f2;">
                    <th style="text-align: left; padding: 8px; border: 1px solid #ddd;">Indicator</th>
                    <th style="text-align: left; padding: 8px; border: 1px solid #ddd;">Severity</th>
                    <th style="text-align: left; padding: 8px; border: 1px solid #ddd;">Description</th>
                </tr>
            """
            
            for indicator in key_indicators:
                html_report += f"""
                <tr>
                    <td style="padding: 8px; border: 1px solid #ddd;">{indicator[0]}</td>
                    <td style="padding: 8px; border: 1px solid #ddd; color: {
                        'red' if indicator[1] == 'High' 
                        else 'orange' if indicator[1] == 'Medium' 
                        else 'black'
                    };">{indicator[1]}</td>
                    <td style="padding: 8px; border: 1px solid #ddd;">{indicator[2]}</td>
                </tr>
                """
            
            html_report += "</table>"
    
    # Display the HTML report
    display(HTML(html_report))
    
    # Create visualizations
    if "ml_features" in features:
        ml_features = features["ml_features"]
        
        # Prepare data for visualizations
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(16, 6))
        
        # Entropy visualization
        labels = ["File", "Strings"]
        entropies = [ml_features.get("entropy", 0), ml_features.get("string_entropy", 0)]
        
        if "section_entropy_mean" in ml_features:
            labels.append("Sections (Mean)")
            entropies.append(ml_features.get("section_entropy_mean", 0))
        
        if "section_entropy_max" in ml_features:
            labels.append("Sections (Max)")
            entropies.append(ml_features.get("section_entropy_max", 0))
        
        # Create entropy bar chart
        bars = ax1.bar(labels, entropies, color='skyblue')
        ax1.axhline(y=7.0, color='red', linestyle='--', alpha=0.7, label='High Entropy Threshold')
        ax1.set_ylim(0, 8.5)
        ax1.set_title('Entropy Analysis')
        ax1.set_ylabel('Entropy (0-8)')
        ax1.legend()
        
        # Add value labels on top of bars
        for bar in bars:
            height = bar.get_height()
            ax1.annotate(f'{height:.2f}',
                         xy=(bar.get_x() + bar.get_width() / 2, height),
                         xytext=(0, 3),  # 3 points vertical offset
                         textcoords="offset points",
                         ha='center', va='bottom')
        
        # Create key indicators radar chart
        categories = ['Packing', 'Anti-Analysis', 'Suspicious APIs', 'RWX Sections', 'Suspicious Strings']
        values = [
            min(1.0, ml_features.get("is_packed", 0) + 0.5 * (ml_features.get("entropy", 0) > 6.5)),
            min(1.0, ml_features.get("anti_analysis_detected", 0)),
            min(1.0, ml_features.get("suspicious_imports", 0) / 10.0),
            min(1.0, ml_features.get("num_rwx_sections", 0) / 2.0),
            min(1.0, ml_features.get("suspicious_string_count", 0) / 10.0)
        ]
        
        # Create radar chart
        values = np.concatenate((values, [values[0]]))  # Close the loop
        categories = np.concatenate((categories, [categories[0]]))  # Close the loop
        
        # Compute angle for each category
        angles = np.linspace(0, 2*np.pi, len(categories)-1, endpoint=False).tolist()
        angles += angles[:1]  # Close the loop
        
        ax2.plot(angles, values, 'o-', linewidth=2, label='Indicators')
        ax2.fill(angles, values, alpha=0.25)
        ax2.set_thetagrids(np.degrees(angles[:-1]), categories[:-1])
        ax2.set_ylim(0, 1)
        ax2.set_title('Key Malware Indicators')
        ax2.grid(True)
        
        plt.tight_layout()
        plt.show()

# Create a simple UI for file analysis
def create_analysis_ui():
    """Create a simple UI for PE file analysis with explanation of results"""
    clear_output(wait=True)
    
    print("=" * 80)
    print("Windows PE File Analyzer with Malware Detection".center(80))
    print("=" * 80)
    print("\nThis tool analyzes Windows PE (Portable Executable) files for potential malware indicators.")
    print("It uses static analysis techniques to identify suspicious patterns and behaviors.\n")
    print("Features:")
    print("  - PE file structure analysis")
    print("  - Entropy analysis for encryption/packing detection")
    print("  - String extraction and analysis")
    print("  - Import/Export analysis")
    print("  - Section analysis")
    print("  - YARA rule matching")
    print("  - Optional ML-based classification (if model is provided)")
    print("\nDisclaimer: This tool provides static analysis only and should not replace")
    print("professional malware analysis tools or antivirus software.\n")
    
    # Create a button to start analysis
    analyze_button = widgets.Button(
        description='Upload and Analyze File',
        button_style='primary',
        tooltip='Click to upload and analyze a PE file'
    )
    
    def on_analyze_button_clicked(b):
        upload_and_analyze()
    
    analyze_button.on_click(on_analyze_button_clicked)
    display(analyze_button)

# Main interface
if __name__ == "__main__":
    # Start analysis UI
    create_analysis_ui()
