from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.db import get_conn
from app.crypto import compute_address_from_public_pem

router = APIRouter()

class RegisterReq(BaseModel):
    address: str
    public_key: str
    vault_encrypted: str | None = None  # MVP, можемо зберігати але не використовуємо

@router.post("/register")
def register_wallet(req: RegisterReq):
    # 1) Перевіряємо що address відповідає public key (захист від підміни)
    expected = compute_address_from_public_pem(req.public_key)
    if req.address != expected:
        raise HTTPException(status_code=400, detail="Address does not match public key")

    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select address from wallets where address=%s", (req.address,))
            if cur.fetchone():
                return {"ok": True, "address": req.address, "already": True}

            cur.execute(
                "insert into wallets(address, public_key, balance, last_nonce) values (%s,%s,0,0)",
                (req.address, req.public_key),
            )
        conn.commit()

    return {"ok": True, "address": req.address, "already": False}

@router.get("/{address}/balance")
def get_balance(address: str):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select balance from wallets where address=%s", (address,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Wallet not found")
            return {"address": address, "balance": int(row[0])}
