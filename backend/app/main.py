from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.routes import wallets, transactions

app = FastAPI(title="SETWALLET OnlyChain", version="1.0.0")

# CORS: дозволяємо Vercel домен + локал
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # потім звузимо до твого домена
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health():
    return {"ok": True}

app.include_router(wallets.router)
app.include_router(transactions.router)
