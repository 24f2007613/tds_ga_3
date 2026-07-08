from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException
from fastapi import status
from fastapi import Request
from fastapi.responses import JSONResponse
from jose import jwt, JWTError

app = FastAPI()

ISSUER = "https://idp.exam.local"
AUDIENCE = "tds-mz0olf8p.apps.exam.local"

PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2okOHspNjgA+2rTLbeuY
cxiP/hG8C6Sb9iwg3yiLAA4HCnpITcbWCSelbvbYGuc3EbNy4xFyf5Cbj5DHJMID
EkryOgyd2giIIIBOUBj8S63uGcnRpOBh9NFatfNwheKuzsPuVNldu6A9cNteNpXc
WyJjG2axVfmq7i6SuKr1JoWYG7xTTAvKPujSl4OtsQfO3h5NepzdfXpr28oNnzfW
ed+zclR6BcmNNo/WVfJ4xyCLSf0BCOgdTgW6PdaChd1l9VDetJZVEgC5tkyvXsfI
SI6iyrYbKR0NEBSqq4XkadEjsCs4F1RncsS4LlgniT7GlkL9Mce3b0wGLs9/7ZIX
dQIDAQAB
-----END PUBLIC KEY-----"""

ALGORITHM = "RS256"


def verify_token(token: str):
    try:
        # Decode and verify signature, issuer, audience, and exp.
        payload = jwt.decode(
            token,
            PUBLIC_KEY,
            algorithms=[ALGORITHM],
            audience=AUDIENCE,
            issuer=ISSUER,
        )
    except JWTError:
        # Any signature/iss/aud/exp error → invalid
        return None

    # Additional manual expiry check (defensive)
    exp = payload.get("exp")
    if exp is None:
        return None
    now_ts = datetime.now(timezone.utc).timestamp()
    if exp < now_ts:
        return None

    return payload


@app.post("/verify")
async def verify(body: dict):
    token = body.get("token")
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing",
        )

    payload = verify_token(token)
    if payload is None:
        # Any invalid token: non-200 with {"valid": false}
        return JSONResponse(
            status_code=status.HTTP_401_UNAUTHORIZED,
            content={"valid": False},
        )

    # Valid token: 200 with claims echoed
    email = payload.get("email")
    sub = payload.get("sub")
    aud = payload.get("aud")

    return {
        "valid": True,
        "email": email,
        "sub": sub,
        "aud": aud,
    }