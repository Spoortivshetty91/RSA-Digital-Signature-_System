
import base64
import hashlib
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed


app = FastAPI(title="RSA Digital Signature System")

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# Demonstration-only in-memory key storage
private_key = None
public_key = None


class MessageRequest(BaseModel):
    message: str


class VerifyRequest(BaseModel):
    message: str
    signature: str
    public_key: str


@app.get("/")
def home():
    return FileResponse(STATIC_DIR / "index.html")


@app.post("/api/generate-keys")
def generate_keys():
    global private_key, public_key

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


@app.post("/api/sign")
def sign_message(data: MessageRequest):
    if private_key is None:
        raise HTTPException(
            status_code=400,
            detail="Generate RSA keys first."
        )

    if not data.message:
        raise HTTPException(
            status_code=400,
            detail="Message cannot be empty."
        )

    # Step 1: Calculate SHA-256 message digest
    digest = hashlib.sha256(
        data.message.encode("utf-8")
    ).digest()

    # Step 2: Sign the digest using RSA-PSS
    signature = private_key.sign(
        digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        Prehashed(hashes.SHA256())
    )

    # Step 3: Encode signature for JSON transmission
    signature_b64 = base64.b64encode(
        signature
    ).decode("ascii")

    return {
        "message": "Message signed successfully",
        "message_hash": digest.hex(),
        "signature": signature_b64
    }


@app.post("/api/verify")
def verify_signature(data: VerifyRequest):
    if not data.message:
        raise HTTPException(
            status_code=400,
            detail="Message cannot be empty."
        )

    try:
        # Step 1: Load the supplied public key
        supplied_public_key = serialization.load_pem_public_key(
            data.public_key.encode("utf-8")
        )

        if not isinstance(
            supplied_public_key,
            rsa.RSAPublicKey
        ):
            raise ValueError("The supplied key is not an RSA public key.")

        # Step 2: Decode the signature
        signature = base64.b64decode(
            data.signature,
            validate=True
        )

        # Step 3: Calculate the hash of the current message
        digest = hashlib.sha256(
            data.message.encode("utf-8")
        ).digest()

        # Step 4: Verify using the public key
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
            detail=f"Invalid input or public key: {error}"
        )

    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Verification failed. Check the key and signature."
        )
