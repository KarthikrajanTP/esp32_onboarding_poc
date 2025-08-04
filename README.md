# ESP32 Onboarding Backend

A secure device onboarding system that verifies device certificates and signatures using PKI (Public Key Infrastructure).

## ⚙️ Setup

### 1. Create a Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
pip install fastapi uvicorn cryptography requests python-multipart
```

### 2. Generate Certificate Authority (CA)

```bash
# Create Manufacturer CA
openssl genrsa -out ca/ca.key 4096
openssl req -x509 -new -nodes -key ca/ca.key -sha256 -days 3650 -out ca/ca.crt \
  -subj "/C=IN/ST=TN/L=Chennai/O=Manufacturer/CN=RootCA"
```

### 3. Generate Device Certificate

```bash
# Generate Device Key + CSR
openssl genpkey -algorithm RSA -out device/device.key -pkeyopt rsa_keygen_bits:2048
openssl req -new -key device/device.key -out device/device.csr \
  -subj "/C=IN/ST=TN/L=Chennai/O=Device/CN=device-001"

# Sign Device Certificate
openssl x509 -req -in device/device.csr -CA ca/ca.crt -CAkey ca/ca.key \
  -CAcreateserial -out device/device.crt -days 365 -sha256
```

## 🚀 Running the Backend

```bash
uvicorn main:app --reload
```

## 📡 Simulate Device Request

```bash
python simulate_device_request.py
```

## 🔐 Security Features

- **Certificate Chain Verification**: Ensures devices have valid CA-signed certificates
- **Digital Signature Verification**: Validates message authenticity using device private keys
- **PKI-based Authentication**: Uses industry-standard public key infrastructure
