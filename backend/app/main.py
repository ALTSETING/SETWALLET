from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes import wallets, transactions

app = FastAPI(title="SETWALLET OnlyChain")

# MVP: allow all. Потім звузимо до домена Vercel.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(wallets.router, prefix="/wallets", tags=["wallets"])
app.include_router(transactions.router, prefix="/tx", tags=["tx"])

@app.get("/")
def root():
    return {"ok": True, "service": "setwallet-backend"}
