import base64
import json
import requests
from datetime import datetime, timezone
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

# === CONFIG ===
DEVICE_KEY_PATH = "device/device.key"
DEVICE_CERT_PATH = "device/device.crt"
BACKEND_URL = "http://127.0.0.1:8000/onboard"

# === 1. Load Device Private Key ===
with open(DEVICE_KEY_PATH, "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(), password=None, backend=default_backend()
    )

# === 2. Load Device Certificate ===
with open(DEVICE_CERT_PATH, "r") as f:
    device_cert = f.read()

# === 3. Construct Onboarding Payload ===
device_id = "device-001"
timestamp = int(datetime.now(timezone.utc).timestamp())
payload = {"weight": 99.9, "unit": "kg"}

# === 4. Generate the Message to Sign ===
# Must match exactly what the backend will verify
message = f"{device_id}:{timestamp}:{payload}".encode()

# === 5. Sign the Message ===
signature = private_key.sign(
    message,
    padding.PKCS1v15(),
    hashes.SHA256()
)
signature_b64 = base64.b64encode(signature).decode()

# === 6. Assemble JSON Request ===
data = {
    "device_id": device_id,
    "timestamp": timestamp,
    "payload": payload,
    "signature": signature_b64,
    "device_cert": device_cert
}

# === 7. Send to FastAPI Server ===
try:
    res = requests.post(BACKEND_URL, json=data)
    print(f"[{res.status_code}] Response: {res.json()}")
except requests.RequestException as e:
    print("Failed to connect to backend:", e)
