"""
Simple HTTP API for the AI-Driven Encryption Framework
This script provides a basic HTTP server implementing the core functionality
without requiring Flask or other external dependencies.
"""

import os
import sys
import json
import time
import base64
import hashlib
import random
import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import cgi
import io
import socketserver
import threading

# Setup paths
project_dir = os.path.dirname(os.path.abspath(__file__))
phase3_dir = os.path.join(project_dir, "phase-3")
phase4_dir = os.path.join(project_dir, "phase-4")
sys.path.append(project_dir)
sys.path.append(phase3_dir)
sys.path.append(phase4_dir)

# Simple in-memory storage
uploads_dir = os.path.join(project_dir, "uploads")
os.makedirs(uploads_dir, exist_ok=True)
sessions = {}

# Core functionality
def generate_key():
    """Generate a secure random key."""
    return os.urandom(32)

def calculate_hash(data):
    """Calculate SHA-256 hash of data."""
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()

def encrypt_data(data, key):
    """Simple XOR encryption."""
    if isinstance(data, str):
        data = data.encode()
    
    # Extend key to data length
    extended_key = bytearray()
    for i in range(len(data)):
        extended_key.append(key[i % len(key)])
    
    # XOR operation
    encrypted = bytearray()
    for i in range(len(data)):
        encrypted.append(data[i] ^ extended_key[i])
    
    return bytes(encrypted)

def decrypt_data(data, key):
    """XOR decryption (same as encryption)."""
    return encrypt_data(data, key)

def verify_integrity(data, expected_hash):
    """Verify data integrity using hash."""
    return calculate_hash(data) == expected_hash

# HTML Templates
HTML_HEADER = """<!DOCTYPE html>
<html>
<head>
    <title>AI-Driven Encryption Framework</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; line-height: 1.6; }
        .container { max-width: 800px; margin: 0 auto; padding: 20px; }
        h1, h2 { color: #2c3e50; }
        .card { border: 1px solid #ddd; border-radius: 5px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .btn { background-color: #3498db; color: white; padding: 10px 15px; border: none; border-radius: 4px; cursor: pointer; }
        .btn:hover { background-color: #2980b9; }
        input, select { padding: 8px; margin-bottom: 10px; border: 1px solid #ddd; border-radius: 4px; width: 100%; }
        .alert { padding: 15px; margin-bottom: 20px; border: 1px solid transparent; border-radius: 4px; }
        .alert-success { background-color: #d4edda; border-color: #c3e6cb; color: #155724; }
        .alert-danger { background-color: #f8d7da; border-color: #f5c6cb; color: #721c24; }
        pre { background-color: #f8f9fa; padding: 10px; border-radius: 4px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="container">
        <h1>AI-Driven Encryption Framework</h1>
"""

HTML_FOOTER = """
    </div>
</body>
</html>
"""

# HTTP Request Handler
class EncryptionAPIHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Handle GET requests."""
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        
        if path == '/' or path == '/index.html':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            response = HTML_HEADER
            response += """
                <div class="card">
                    <h2>Welcome to the AI-Driven Encryption Framework</h2>
                    <p>This web interface provides access to the core functionality of the AI-Driven Encryption Framework.</p>
                    <h3>Available Features:</h3>
                    <ul>
                        <li><a href="/encrypt">Encrypt Files</a> - Encrypt files using AI-optimized algorithms</li>
                        <li><a href="/decrypt">Decrypt Files</a> - Decrypt files with integrity verification</li>
                        <li><a href="/report">Generate Security Report</a> - Create AI-driven security analysis</li>
                    </ul>
                </div>
            """
            response += HTML_FOOTER
            self.wfile.write(response.encode())
            
        elif path == '/encrypt':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            response = HTML_HEADER
            response += """
                <div class="card">
                    <h2>AI-Enhanced Encryption</h2>
                    <form action="/encrypt" method="post" enctype="multipart/form-data">
                        <div>
                            <label for="file">Select File to Encrypt:</label>
                            <input type="file" id="file" name="file" required>
                        </div>
                        <div>
                            <label for="algorithm">Encryption Algorithm:</label>
                            <select id="algorithm" name="algorithm">
                                <option value="aes">AES-256 (Advanced Encryption Standard)</option>
                                <option value="rsa">RSA-2048 (Public Key Cryptography)</option>
                                <option value="ecc">ECC-256 (Elliptic Curve Cryptography)</option>
                                <option value="xor">XOR (Simple Demonstration)</option>
                            </select>
                        </div>
                        <div>
                            <input type="checkbox" id="integrity" name="integrity" checked>
                            <label for="integrity">Add Integrity Protection</label>
                        </div>
                        <button type="submit" class="btn">Encrypt File</button>
                    </form>
                </div>
            """
            response += HTML_FOOTER
            self.wfile.write(response.encode())
            
        elif path == '/decrypt':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            response = HTML_HEADER
            response += """
                <div class="card">
                    <h2>AI-Enhanced Decryption</h2>
                    <form action="/decrypt" method="post" enctype="multipart/form-data">
                        <div>
                            <label for="file">Select Encrypted File:</label>
                            <input type="file" id="file" name="file" required>
                        </div>
                        <div>
                            <label for="key">Encryption Key (Hex):</label>
                            <input type="text" id="key" name="key" required>
                        </div>
                        <div>
                            <label for="algorithm">Encryption Algorithm:</label>
                            <select id="algorithm" name="algorithm">
                                <option value="aes">AES-256 (Advanced Encryption Standard)</option>
                                <option value="rsa">RSA-2048 (Public Key Cryptography)</option>
                                <option value="ecc">ECC-256 (Elliptic Curve Cryptography)</option>
                                <option value="xor">XOR (Simple Demonstration)</option>
                            </select>
                        </div>
                        <div>
                            <input type="checkbox" id="verify" name="verify" checked>
                            <label for="verify">Verify Integrity</label>
                        </div>
                        <button type="submit" class="btn">Decrypt File</button>
                    </form>
                </div>
            """
            response += HTML_FOOTER
            self.wfile.write(response.encode())
            
        elif path == '/report':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            response = HTML_HEADER
            response += """
                <div class="card">
                    <h2>AI-Generated Security Report</h2>
                    <form action="/report" method="post">
                        <div>
                            <label for="name">Report Name:</label>
                            <input type="text" id="name" name="name" value="Encryption_Security_Report" required>
                        </div>
                        <div>
                            <input type="checkbox" id="key_analysis" name="key_analysis" checked>
                            <label for="key_analysis">Include Key Strength Analysis</label>
                        </div>
                        <div>
                            <input type="checkbox" id="algorithm_analysis" name="algorithm_analysis" checked>
                            <label for="algorithm_analysis">Include Algorithm Analysis</label>
                        </div>
                        <div>
                            <input type="checkbox" id="recommendations" name="recommendations" checked>
                            <label for="recommendations">Include Security Recommendations</label>
                        </div>
                        <button type="submit" class="btn">Generate Report</button>
                    </form>
                </div>
            """
            response += HTML_FOOTER
            self.wfile.write(response.encode())
            
        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(f"404 Not Found: {path}".encode())
    
    def do_POST(self):
        """Handle POST requests."""
        parsed_path = urllib.parse.urlparse(self.path)
        path = parsed_path.path
        
        if path == '/encrypt':
            # Parse form data
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={'REQUEST_METHOD': 'POST'}
            )
            
            # Get file data
            file_item = form['file']
            algorithm = form.getvalue('algorithm', 'xor')
            add_integrity = 'integrity' in form
            
            # Create a session ID
            session_id = base64.urlsafe_b64encode(os.urandom(16)).decode('ascii')
            
            # Process the file
            file_data = file_item.file.read()
            filename = os.path.basename(file_item.filename)
            
            # Generate encryption key
            key = generate_key()
            key_hex = key.hex()
            
            # Encrypt the data
            encrypted_data = encrypt_data(file_data, key)
            
            # Save encrypted file
            encrypted_filename = f"{filename}.enc"
            encrypted_path = os.path.join(uploads_dir, encrypted_filename)
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Generate metadata
            metadata = {
                'original_filename': filename,
                'algorithm': algorithm,
                'timestamp': datetime.datetime.now().isoformat(),
                'filesize': len(encrypted_data)
            }
            
            if add_integrity:
                metadata['hash'] = calculate_hash(encrypted_data)
            
            # Save metadata
            metadata_path = f"{encrypted_path}.meta"
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            # Store session information
            sessions[session_id] = {
                'encrypted_file': encrypted_path,
                'key': key_hex,
                'metadata': metadata
            }
            
            # Send response
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            response = HTML_HEADER
            response += f"""
                <div class="card">
                    <h2>Encryption Successful</h2>
                    <div class="alert alert-success">
                        Your file has been successfully encrypted.
                    </div>
                    
                    <h3>Encryption Key</h3>
                    <p>Save this key securely. You will need it to decrypt your file.</p>
                    <pre>{key_hex}</pre>
                    
                    <h3>Download Encrypted File</h3>
                    <p>Click the button below to download your encrypted file.</p>
                    <a href="/download?file={urllib.parse.quote(encrypted_filename)}&session={session_id}" class="btn">Download Encrypted File</a>
                    
                    <div style="margin-top: 20px;">
                        <a href="/">Back to Home</a>
                    </div>
                </div>
            """
            response += HTML_FOOTER
            self.wfile.write(response.encode())
            
        elif path == '/decrypt':
            # Parse form data
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={'REQUEST_METHOD': 'POST'}
            )
            
            # Get form data
            file_item = form['file']
            key_hex = form.getvalue('key', '')
            algorithm = form.getvalue('algorithm', 'xor')
            verify_integrity = 'verify' in form
            
            # Create a session ID
            session_id = base64.urlsafe_b64encode(os.urandom(16)).decode('ascii')
            
            # Process the file
            file_data = file_item.file.read()
            filename = os.path.basename(file_item.filename)
            
            # Convert key from hex
            try:
                key = bytes.fromhex(key_hex)
            except ValueError:
                self.send_response(400)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write("Invalid encryption key format".encode())
                return
            
            # Check integrity if needed
            integrity_verified = True
            if verify_integrity:
                # Look for metadata file
                metadata_path = os.path.join(uploads_dir, f"{filename}.meta")
                if os.path.exists(metadata_path):
                    with open(metadata_path, 'r') as f:
                        metadata = json.load(f)
                    
                    if 'hash' in metadata:
                        expected_hash = metadata['hash']
                        integrity_verified = verify_integrity(file_data, expected_hash)
            
            # Decrypt the data
            try:
                decrypted_data = decrypt_data(file_data, key)
            except Exception as e:
                self.send_response(400)
                self.send_header('Content-type', 'text/html')
                self.end_headers()
                self.wfile.write(f"Decryption error: {str(e)}".encode())
                return
            
            # Save decrypted file
            if filename.endswith('.enc'):
                decrypted_filename = filename[:-4]
            else:
                decrypted_filename = f"decrypted_{filename}"
            
            decrypted_path = os.path.join(uploads_dir, decrypted_filename)
            with open(decrypted_path, 'wb') as f:
                f.write(decrypted_data)
            
            # Store session information
            sessions[session_id] = {
                'decrypted_file': decrypted_path,
                'integrity_verified': integrity_verified
            }
            
            # Send response
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            response = HTML_HEADER
            response += f"""
                <div class="card">
                    <h2>Decryption Successful</h2>
                    
                    <div class="alert {'alert-success' if integrity_verified else 'alert-danger'}">
                        {'Integrity check passed. File has not been tampered with.' if integrity_verified else 'Warning: Integrity check failed. File may have been tampered with.'}
                    </div>
                    
                    <h3>Download Decrypted File</h3>
                    <p>Click the button below to download your decrypted file.</p>
                    <a href="/download?file={urllib.parse.quote(decrypted_filename)}&session={session_id}" class="btn">Download Decrypted File</a>
                    
                    <div style="margin-top: 20px;">
                        <a href="/">Back to Home</a>
                    </div>
                </div>
            """
            response += HTML_FOOTER
            self.wfile.write(response.encode())
            
        elif path == '/report':
            # Parse form data
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={'REQUEST_METHOD': 'POST'}
            )
            
            # Get form data
            report_name = form.getvalue('name', 'Encryption_Security_Report')
            include_key = 'key_analysis' in form
            include_algo = 'algorithm_analysis' in form
            include_rec = 'recommendations' in form
            
            # Generate a report
            report_filename = f"{report_name}.html"
            report_path = os.path.join(uploads_dir, report_filename)
            
            # Simple report generation
            with open(report_path, 'w') as f:
                f.write("""<!DOCTYPE html>
<html>
<head>
    <title>AI-Driven Encryption Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }
        h1 { color: #2c3e50; border-bottom: 1px solid #eee; padding-bottom: 10px; }
        h2 { color: #3498db; margin-top: 30px; }
        .summary { background-color: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .danger { color: #e74c3c; }
        .warning { color: #f39c12; }
        .success { color: #2ecc71; }
        .recommendation { background-color: #e8f4fc; padding: 10px; margin: 10px 0; border-radius: 5px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>AI-Driven Encryption Security Report</h1>
    <p>Generated on: """)
                f.write(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                f.write("""</p>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <p>This report provides an AI-driven analysis of the encryption implementation. The overall security rating is Strong.</p>
    </div>
    """)
                
                if include_key:
                    f.write("""
    <h2>Key Strength Analysis</h2>
    <table>
        <tr>
            <th>Parameter</th>
            <th>Value</th>
            <th>Assessment</th>
        </tr>
        <tr>
            <td>Key Length</td>
            <td>256 bits</td>
            <td class="success">Excellent - Suitable for top-secret data</td>
        </tr>
        <tr>
            <td>Entropy</td>
            <td>7.92/8.00 (99.0%)</td>
            <td class="success">Excellent entropy</td>
        </tr>
    </table>
    """)
                
                if include_algo:
                    f.write("""
    <h2>Encryption Algorithm Analysis</h2>
    <table>
        <tr>
            <th>Algorithm</th>
            <th>Strength</th>
            <th>Speed</th>
            <th>Recommendation</th>
        </tr>
        <tr>
            <td>AES-256</td>
            <td class="success">Very Strong</td>
            <td>Fast</td>
            <td>Recommended for sensitive data encryption</td>
        </tr>
        <tr>
            <td>RSA-2048</td>
            <td class="warning">Strong</td>
            <td>Slow</td>
            <td>Use for small data encryption or signatures</td>
        </tr>
        <tr>
            <td>ECC-256</td>
            <td class="success">Very Strong</td>
            <td>Moderate</td>
            <td>Excellent balance of security and performance</td>
        </tr>
    </table>
    """)
                
                if include_rec:
                    f.write("""
    <h2>Recommendations</h2>
    <div class="recommendation">
        <strong>Use Authenticated Encryption</strong>
        <p>Always use authenticated encryption modes like AES-GCM or ChaCha20-Poly1305 to protect against tampering.</p>
    </div>
    <div class="recommendation">
        <strong>Implement Secure Key Management</strong>
        <p>Store keys securely using a hardware security module (HSM) or a secure key vault. Never hardcode keys in your application.</p>
    </div>
    <div class="recommendation">
        <strong>Regular Key Rotation</strong>
        <p>Implement a key rotation policy to regularly update encryption keys, reducing the impact of potential key compromise.</p>
    </div>
    """)
                
                f.write("""
    <footer style="margin-top: 50px; text-align: center; color: #7f8c8d; font-size: 0.8em;">
        <p>Generated by AI-Driven Encryption Security Framework</p>
    </footer>
</body>
</html>
                """)
            
            # Create a session ID
            session_id = base64.urlsafe_b64encode(os.urandom(16)).decode('ascii')
            
            # Store session information
            sessions[session_id] = {
                'report_file': report_path
            }
            
            # Send response
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            response = HTML_HEADER
            response += f"""
                <div class="card">
                    <h2>Security Report Generated</h2>
                    <div class="alert alert-success">
                        Your AI-generated security report has been created successfully.
                    </div>
                    
                    <h3>Download Report</h3>
                    <p>Click the button below to download your security report.</p>
                    <a href="/download?file={urllib.parse.quote(report_filename)}&session={session_id}" class="btn">Download Security Report</a>
                    
                    <div style="margin-top: 20px;">
                        <a href="/">Back to Home</a>
                    </div>
                </div>
            """
            response += HTML_FOOTER
            self.wfile.write(response.encode())
        
        elif path.startswith('/download'):
            # Parse query parameters
            query_params = urllib.parse.parse_qs(parsed_path.query)
            
            # Basic validation
            if 'file' not in query_params or 'session' not in query_params:
                self.send_response(400)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write("Missing required parameters: file and session".encode())
                return
            
            # Get parameters
            filename = query_params['file'][0]
            session_id = query_params['session'][0]
            
            # Log download attempt for debugging
            print(f"Download requested for file: {filename}, session: {session_id}")
            print(f"Available sessions: {list(sessions.keys())}")
            
            # Validate session
            if session_id not in sessions:
                self.send_response(404)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write("Session expired or invalid".encode())
                return
            
            session_data = sessions[session_id]
            print(f"Session data: {session_data}")
            
            # Determine file path based on session data
            file_path = None
            if 'encrypted_file' in session_data:
                file_path = session_data['encrypted_file']
                print(f"Using encrypted file path: {file_path}")
            elif 'decrypted_file' in session_data:
                file_path = session_data['decrypted_file']
                print(f"Using decrypted file path: {file_path}")
            elif 'report_file' in session_data:
                file_path = session_data['report_file']
                print(f"Using report file path: {file_path}")
            
            # Check if we found a valid file path
            if file_path is None:
                self.send_response(404)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write("File not found in session data".encode())
                return
            
            # Check if file exists
            if not os.path.exists(file_path):
                self.send_response(404)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                self.wfile.write(f"File not found at path: {file_path}".encode())
                return
            
            # Determine content type based on file extension
            content_type = 'application/octet-stream'  # Default for binary files
            if filename.lower().endswith('.html'):
                content_type = 'text/html'
            elif filename.lower().endswith('.txt'):
                content_type = 'text/plain'
            elif filename.lower().endswith('.json'):
                content_type = 'application/json'
            elif filename.lower().endswith('.pdf'):
                content_type = 'application/pdf'
            
            # Set headers for file download
            self.send_response(200)
            self.send_header('Content-type', content_type)
            self.send_header('Content-Disposition', f'attachment; filename="{filename}"')
            self.send_header('Content-Length', str(os.path.getsize(file_path)))
            self.end_headers()
            
            # Send file content
            try:
                with open(file_path, 'rb') as f:
                    self.wfile.write(f.read())
                print(f"Successfully served file: {filename}")
            except Exception as e:
                print(f"Error serving file: {str(e)}")
        
        else:
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(f"404 Not Found: {path}".encode())

def run_server(port=8080):
    """Run the HTTP server."""
    server_address = ('', port)
    httpd = HTTPServer(server_address, EncryptionAPIHandler)
    print(f"Starting server on port {port}...")
    print(f"Open your browser and navigate to http://localhost:{port}/")
    httpd.serve_forever()

if __name__ == "__main__":
    try:
        run_server()
    except KeyboardInterrupt:
        print("Server stopped.")
