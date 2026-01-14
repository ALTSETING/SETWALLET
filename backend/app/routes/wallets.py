from fastapi import APIRouter, HTTPException
from app.schemas import RegisterWallet
from app.db import get_conn
from app.ledger import get_balance

router = APIRouter(prefix="/wallets", tags=["wallets"])

@router.post("/register")
def register_wallet(body: RegisterWallet):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select address from public.wallets where address=%s", (body.address,))
            if cur.fetchone():
                return {"ok": True, "address": body.address}

            cur.execute(
                "insert into public.wallets(address, public_key) values (%s,%s)",
                (body.address, body.public_key),
            )
        conn.commit()
    return {"ok": True, "address": body.address}

@router.get("/{address}/balance")
def balance(address: str):
    return {"address": address, "balance": get_balance(address)}
