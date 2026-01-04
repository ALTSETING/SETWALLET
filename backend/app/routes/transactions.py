import hashlib
from fastapi import APIRouter, HTTPException, Query
from app.schemas import SendTx
from app.db import get_conn
from app.crypto import verify_signature
from app.ledger import get_balance

router = APIRouter(prefix="/tx", tags=["tx"])

@router.post("/send")
def send_tx(body: SendTx):
    # 1) простий message формат (має збігатися з фронтом)
    msg = f"{body.from_address}:{body.to_address}:{body.amount}:{body.nonce}".encode("utf-8")

    # 2) verify signature
    if not verify_signature(body.public_key, msg, body.signature):
        raise HTTPException(status_code=400, detail="Invalid signature")

    # 3) check wallet exists + public key matches (захист від підміни)
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("select public_key_pem from public.wallets where address=%s", (body.from_address,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=400, detail="Sender not registered")
            if row[0].strip() != body.public_key.strip():
                raise HTTPException(status_code=400, detail="Public key mismatch")

            # 4) balance check
            bal = get_balance(body.from_address)
            if bal < body.amount:
                raise HTTPException(status_code=400, detail="Insufficient balance")

            # 5) tx_id (детермінований)
            tx_id = hashlib.sha256(msg + body.signature.encode("utf-8")).hexdigest()[:24]

            # 6) nonce anti-replay: перевіряємо що nonce > max nonce для from_address
            cur.execute("select coalesce(max(nonce),0) from public.ledger where from_address=%s", (body.from_address,))
            max_nonce = int(cur.fetchone()[0] or 0)
            if body.nonce <= max_nonce:
                raise HTTPException(status_code=400, detail="Bad nonce")

            # 7) insert ledger
            cur.execute(
                """
                insert into public.ledger(tx_id, from_address, to_address, amount, nonce, memo)
                values (%s,%s,%s,%s,%s,%s)
                """,
                (tx_id, body.from_address, body.to_address, body.amount, body.nonce, body.memo),
            )
        conn.commit()

    return {"ok": True, "tx_id": tx_id}

@router.get("/history/{address}")
def history(address: str, limit: int = Query(50, ge=1, le=200)):
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                select tx_id, from_address, to_address, amount, nonce, memo, created_at
                from public.ledger
                where from_address = %s or to_address = %s
                order by created_at desc
                limit %s
                """,
                (address, address, limit),
            )
            rows = cur.fetchall()

    items = []
    for r in rows:
        items.append({
            "tx_id": r[0],
            "from_address": r[1],
            "to_address": r[2],
            "amount": int(r[3]),
            "nonce": int(r[4]),
            "memo": r[5],
            "created_at": r[6].isoformat() if r[6] else None,
        })

    return {"address": address, "items": items}
