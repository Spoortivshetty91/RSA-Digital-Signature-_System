
import base64
import hashlib
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed


# --------------------------------------------------
# 1. Initialize FastAPI
# --------------------------------------------------

app = FastAPI(title="RSA Digital Signature System")

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

if not STATIC_DIR.is_dir():
    raise RuntimeError(
        f"Static folder not found: {STATIC_DIR}"
    )

app.mount(
    "/static",
    StaticFiles(directory=STATIC_DIR),
    name="static"
)

# Demonstration-only in-memory storage
private_key = None
public_key = None


# --------------------------------------------------
# 2. Request models
# --------------------------------------------------

class MessageRequest(BaseModel):
    message: str = Field(min_length=1)


class VerifyRequest(BaseModel):
    message: str = Field(min_length=1)
    signature: str = Field(min_length=1)
    public_key: str = Field(min_length=1)


# --------------------------------------------------
# 3. Home page
# --------------------------------------------------

@app.get("/")
def home():
    return FileResponse(STATIC_DIR / "index.html")


# --------------------------------------------------
# 4. Health check
# --------------------------------------------------

@app.get("/api/health")
def health_check():
    return {
        "status": "running",
        "message": "RSA Digital Signature backend is working"
    }


# --------------------------------------------------
# 5. Generate RSA keys
# --------------------------------------------------

@app.post("/api/generate-keys")
def generate_keys():
    global private_key, public_key

    try:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        public_key = private_key.public_key()

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

        return {
            "message": "RSA key pair generated successfully",
            "public_key": public_pem
        }

    except Exception as error:
        private_key = None
        public_key = None

        raise HTTPException(
            status_code=500,
            detail=f"RSA key generation failed: {error}"
        )


# --------------------------------------------------
# 6. Sign message
# --------------------------------------------------

@app.post("/api/sign")
def sign_message(data: MessageRequest):
    if private_key is None:
        raise HTTPException(
            status_code=400,
            detail="Generate RSA keys first."
        )

    try:
        digest = hashlib.sha256(
            data.message.encode("utf-8")
        ).digest()

        signature = private_key.sign(
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            Prehashed(hashes.SHA256())
        )

        signature_b64 = base64.b64encode(
            signature
        ).decode("ascii")

        return {
            "message": "Message signed successfully",
            "message_hash": digest.hex(),
            "signature": signature_b64
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=f"Signing failed: {error}"
        )


# --------------------------------------------------
# 7. Verify signature
# --------------------------------------------------

@app.post("/api/verify")
def verify_signature(data: VerifyRequest):
    try:
        supplied_public_key = serialization.load_pem_public_key(
            data.public_key.encode("utf-8")
        )

        if not isinstance(
            supplied_public_key,
            rsa.RSAPublicKey
        ):
            raise ValueError(
                "The supplied key is not an RSA public key."
            )

        signature = base64.b64decode(
            data.signature,
            validate=True
        )

        digest = hashlib.sha256(
            data.message.encode("utf-8")
        ).digest()

        supplied_public_key.verify(
            signature,
            digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            Prehashed(hashes.SHA256())
        )

        return {
            "valid": True,
            "message": "Valid signature. The message matches the signature."
        }

    except InvalidSignature:
        return {
            "valid": False,
            "message": "Invalid signature. The message may have been modified."
        }

    except (ValueError, TypeError) as error:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid signature input or public key: {error}"
        )

    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Verification failed. Check the message, key, and signature."
        )
