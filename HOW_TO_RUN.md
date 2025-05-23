# How to Run the AI-Driven Encryption Framework

This guide provides instructions for running the different components of the AI-Driven Encryption Framework.

## Option 1: Run the Simplified Demo (No Dependencies Required)

The simplified demo demonstrates all five phases of the framework without requiring any external dependencies:

```bash
python simplified_demo.py
```

This will:
- Demonstrate AI-Enhanced Cryptanalysis (Phase 1)
- Show AI-Powered Key Generation (Phase 2)
- Perform AI-Optimized Encryption/Decryption (Phase 3)
- Demonstrate AI-Assisted Data Integrity checking (Phase 4)
- Generate an AI-based Security Report (Phase 5)

## Option 2: Run Individual Phase Components

### Phase 4: File Integrity Application

To run the file integrity application from Phase 4:

```bash
cd phase-4
python file_integrity_app.py protect <your_file> --key <your_secret_key>
```

To verify a file:

```bash
cd phase-4
python file_integrity_app.py verify <your_file> --key <your_secret_key>
```

### Phase 5: Web Application

To run the web application from Phase 5, you'll need to install the required dependencies first:

```bash
pip install flask flask-wtf cryptography
```

Then run the application:

```bash
cd phase-5
python app.py
```

The web interface should be available at http://localhost:5000

## Option 3: Run the Security Enhancement Tool

The security enhancement tool checks for vulnerabilities and enhances the security of your project:

```bash
python secure_project.py --check-all
```

## Troubleshooting

If you encounter issues with missing dependencies:

1. Install the minimal required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. If you're having issues with creating a virtual environment, you can install the dependencies globally and run the simplified demo, which works without any external dependencies.

3. If you specifically need to run the web application (Phase 5) and are having dependency issues, focus on installing just Flask:
   ```bash
   pip install flask
   ```

## Testing

To test the integrity checking functionality:

```bash
python test_integrity.py
```

This will demonstrate the ability to detect tampering in files using the framework's integrity checking mechanisms.
