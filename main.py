from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict
import base64
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, ec
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

app = FastAPI()

MANUFACTURER_CA_PATH = "ca/ca.crt"


class OnboardingRequest(BaseModel):
    device_id: str
    timestamp: int
    payload: Dict
    signature: str
    device_cert: str


def load_ca_cert():
    with open(MANUFACTURER_CA_PATH, "rb") as f:
        return x509.load_pem_x509_certificate(f.read(), default_backend())


def verify_certificate_chain(device_cert_pem: str):
    device_cert = x509.load_pem_x509_certificate(device_cert_pem.encode(), default_backend())
    ca_cert = load_ca_cert()

    # Verify device cert is signed by CA
    try:
        ca_cert.public_key().verify(
            signature=device_cert.signature,
            data=device_cert.tbs_certificate_bytes,
            padding=padding.PKCS1v15(),
            algorithm=device_cert.signature_hash_algorithm
        )
    except InvalidSignature:
        raise HTTPException(status_code=400, detail="Invalid certificate signature")

    return device_cert


def verify_signature(device_cert, message_bytes: bytes, signature_b64: str):
    signature = base64.b64decode(signature_b64)
    public_key = device_cert.public_key()

    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                signature,
                message_bytes,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                signature,
                message_bytes,
                ec.ECDSA(hashes.SHA256())
            )
        else:
            raise HTTPException(status_code=400, detail="Unsupported public key type")
    except InvalidSignature:
        raise HTTPException(status_code=400, detail="Invalid payload signature")


@app.post("/onboard")
async def onboard(req: OnboardingRequest):
    # Step 1: Verify the certificate is signed by the trusted CA
      = verify_certificate_chain(req.device_cert)

    # Step 2: Verify the message signature
    message = f"{req.device_id}:{req.timestamp}:{req.payload}".encode()
    verify_signature(device_cert, message, req.signature)

    # Step 3: Respond with success
    return {"status": "onboarded", "device_id": req.device_id}
