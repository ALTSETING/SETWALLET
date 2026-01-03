
from fastapi import FastAPI
from app.routes import wallets, transactions

app = FastAPI(title="SETWALLET OnlyChain")

app.include_router(wallets.router)
app.include_router(transactions.router)
