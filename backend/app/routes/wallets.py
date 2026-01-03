from fastapi import APIRouter, HTTPException
from app.db import get_conn
from app.schemas import RegisterWallet
from app.ledger import get_balance

router = APIRouter(prefix="/wallets")

@router.post("/register")
def register_wallet(data: RegisterWallet):
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO wallets (address, public_key, vault_encrypted)
                VALUES (%s, %s, %s)
                ON CONFLICT (address) DO NOTHING
                """,
                (data.address, data.public_key, data.vault_encrypted)
            )
        conn.commit()
        return {"status": "ok"}
    finally:
        conn.close()

@router.get("/{address}/balance")
def balance(address: str):
    conn = get_conn()
    try:
        bal = get_balance(conn, address)
        return {"address": address, "balance": bal}
    finally:
        conn.close()

