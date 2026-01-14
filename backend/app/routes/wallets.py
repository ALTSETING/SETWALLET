from fastapi import APIRouter, HTTPException
from app.schemas import RegisterWallet
from app.db import get_conn, DatabaseConnectionError
from app.ledger import get_balance

router = APIRouter(prefix="/wallets", tags=["wallets"])
DB_UNAVAILABLE_MESSAGE = "Database unavailable. Check DATABASE_URL credentials."

@router.post("/register")
def register_wallet(body: RegisterWallet):
    try:
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
    except DatabaseConnectionError:
        raise HTTPException(503, DB_UNAVAILABLE_MESSAGE)

@router.get("/{address}/balance")
def balance(address: str):
    try:
        return {"address": address, "balance": get_balance(address)}
    except DatabaseConnectionError:
        raise HTTPException(503, DB_UNAVAILABLE_MESSAGE)
