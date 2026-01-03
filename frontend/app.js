console.log("[SETWALLET] app.js loaded ✅");

const API_BASE = "https://setwallet.onrender.com"; // <- якщо інший Render URL, зміни тут
const LS_WALLET = "setwallet_wallet_v2";
const LS_NONCE  = "setwallet_last_nonce_v2";

// ---------- helpers ----------
const $ = (id) => document.getElementById(id);

function setDebug(text){
  const box = $("debugBox");
  box.textContent = text;
}

function addDebug(line){
  const box = $("debugBox");
  box.textContent += (box.textContent ? "\n" : "") + line;
}

function toast(id, msg){
  const el = $(id);
  el.textContent = msg;
  el.classList.remove("hidden");
  setTimeout(()=> el.classList.add("hidden"), 7000);
}

function show(view){
  const views = ["Welcome","Create","Import","Wallet","Send","Receive","Scan"];
  for(const v of views){
    const el = $("view"+v);
    if(el) el.classList.add("hidden");
  }
  const target = $("view"+view);
  if(target) target.classList.remove("hidden");

  const hasWallet = !!loadWallet();
  $("btnLogout").classList.toggle("hidden", !hasWallet);
}

// ---------- API ----------
async function apiPing(){
  try{
    const r = await fetch(API_BASE + "/openapi.json", { method:"GET" });
    return r.ok;
  }catch(e){
    return false;
  }
}

async function apiRegisterWallet(address, public_key, vault_encrypted=null){
  const r = await fetch(API_BASE + "/wallets/register", {
    method:"POST",
    headers:{ "Content-Type":"application/json" },
    body: JSON.stringify({ address, public_key, vault_encrypted })
  });
  const j = await r.json().catch(()=> ({}));
  if(!r.ok) throw new Error(j.detail || "Register failed");
  return j;
}

async function apiGetBalance(address){
  const r = await fetch(API_BASE + `/wallets/${encodeURIComponent(address)}/balance`);
  const j = await r.json().catch(()=> ({}));
  if(!r.ok) throw new Error(j.detail || "Balance failed");
  return Number(j.balance ?? 0);
}

async function apiSendTx(payload){
  const r = await fetch(API_BASE + "/tx/send", {
    method:"POST",
    headers:{ "Content-Type":"application/json" },
    body: JSON.stringify(payload)
  });
  const j = await r.json().catch(()=> ({}));
  if(!r.ok) throw new Error(j.detail || "Send failed");
  return j;
}

// ---------- crypto ----------
function bufToB64(buf){
  const bytes = new Uint8Array(buf);
  let bin = "";
  for(const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}
function b64ToBuf(b64){
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}
function ab2hex(buffer){
  return [...new Uint8Array(buffer)].map(b=>b.toString(16).padStart(2,'0')).join('');
}
function pemWrap(label, derBytes){
  const b64 = bufToB64(derBytes);
  const lines = b64.match(/.{1,64}/g).join("\n");
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----\n`;
}
async function exportPublicPem(pubKey){
  const spki = await crypto.subtle.exportKey("spki", pubKey);
  return pemWrap("PUBLIC KEY", spki);
}
async function exportPrivatePem(privKey){
  const pkcs8 = await crypto.subtle.exportKey("pkcs8", privKey);
  return pemWrap("PRIVATE KEY", pkcs8);
}
async function generateKeypair(){
  return crypto.subtle.generateKey(
    { name:"ECDSA", namedCurve:"P-256" },
    true,
    ["sign","verify"]
  );
}
async function sha256(data){
  return crypto.subtle.digest("SHA-256", data);
}
async function addressFromPublicPem(pubPem){
  const enc = new TextEncoder();
  const hash = await sha256(enc.encode(pubPem));
  const hex = ab2hex(hash);
  return "SET" + hex.slice(0, 40);
}
async function signMessage(privKey, msgBytes){
  const sig = await crypto.subtle.sign({ name:"ECDSA", hash:"SHA-256" }, privKey, msgBytes);
  return bufToB64(sig);
}
function pemToDer(pem){
  const lines = pem.trim().split("\n");
  const b64 = lines.filter(l=>!l.startsWith("-----")).join("");
  return b64ToBuf(b64);
}
async function importPrivatePem(pem){
  const der = pemToDer(pem);
  return crypto.subtle.importKey("pkcs8", der, { name:"ECDSA", namedCurve:"P-256" }, true, ["sign"]);
}

// ---------- local wallet ----------
function saveWallet(w){
  localStorage.setItem(LS_WALLET, JSON.stringify(w));
}
function loadWallet(){
  try{
    const raw = localStorage.getItem(LS_WALLET);
    if(!raw) return null;
    const w = JSON.parse(raw);
    return w?.address ? w : null;
  }catch{ return null; }
}
function clearWallet(){
  localStorage.removeItem(LS_WALLET);
  localStorage.removeItem(LS_NONCE);
}
function getNextNonce(){
  const now = Date.now();
  const last = Number(localStorage.getItem(LS_NONCE) || "0");
  const nonce = Math.max(now, last + 1);
  localStorage.setItem(LS_NONCE, String(nonce));
  return nonce;
}

// ---------- QR ----------
let qrObj = null;
function makeQrPayload(address){
  return JSON.stringify({ v:1, type:"setwallet_transfer", to: address });
}
function renderQR(address){
  const payload = makeQrPayload(address);
  $("qrPayload").value = payload;
  $("qr").innerHTML = "";
  qrObj = new QRCode($("qr"), { text: payload, width: 220, height: 220 });
}

// ---------- scanner ----------
let qrScanner = null;
async function startScan(){
  try{
    $("scanMsg").classList.add("hidden");
    if(qrScanner) return;

    qrScanner = new Html5Qrcode("scanner");
    const devices = await Html5Qrcode.getCameras();
    const cameraId = devices?.[0]?.id;
    if(!cameraId){
      toast("scanMsg","Камеру не знайдено");
      return;
    }

    await qrScanner.start(
      cameraId,
      { fps: 10, qrbox: { width: 250, height: 250 } },
      (decodedText) => {
        try{
          const data = JSON.parse(decodedText);
          if(data?.to){
            $("sendTo").value = data.to;
            toast("scanMsg","QR зчитано ✅");
            stopScan();
            show("Send");
          } else {
            toast("scanMsg","QR не схожий на SETWALLET");
          }
        }catch{
          toast("scanMsg","QR не JSON");
        }
      }
    );
  }catch(e){
    toast("scanMsg","Scan error: " + e.message);
  }
}
async function stopScan(){
  if(!qrScanner) return;
  try{ await qrScanner.stop(); }catch{}
  try{ await qrScanner.clear(); }catch{}
  qrScanner = null;
}

// ---------- UI actions ----------
async function refreshWalletUI(){
  const meta = loadWallet();
  if(!meta){
    show("Welcome");
    return;
  }

  $("walletAddr").textContent = meta.address;
  $("walletPub").value = meta.public_key_pem || "";

  // balance
  try{
    const bal = await apiGetBalance(meta.address);
    $("walletBal").textContent = String(bal);
  }catch(e){
    $("walletBal").textContent = "0";
    addDebug("[balance] " + e.message);
  }
}

// ---------- boot ----------
async function boot(){
  // Debug visible text
  setDebug("boot() started...\nAPI_BASE=" + API_BASE);

  // Debug toggle
  $("btnToggleDebug").onclick = ()=>{
    $("debugBox").classList.toggle("hidden");
  };

  // nav buttons
  document.addEventListener("click", (e)=>{
    const btn = e.target.closest("[data-nav]");
    if(!btn) return;
    const to = btn.getAttribute("data-nav");
    if(to === "scan") startScan();
    else stopScan();
    show(to[0].toUpperCase() + to.slice(1));
  });

  // top actions
  $("btnLogout").onclick = ()=>{
    stopScan();
    clearWallet();
    show("Welcome");
  };

  // welcome
  $("btnCreate").onclick = ()=> show("Create");
  $("btnImport").onclick = ()=> show("Import");

  // create
  $("btnDoCreate").onclick = async ()=>{
    try{
      $("createOut").classList.add("hidden");
      $("createMsg").classList.add("hidden");

      const kp = await generateKeypair();
      const pubPem = await exportPublicPem(kp.publicKey);
      const privPem = await exportPrivatePem(kp.privateKey);
      const address = await addressFromPublicPem(pubPem);

      // MVP store (без шифрування тут; якщо хочеш — додамо AES як у твоєму старому коді)
      saveWallet({
        address,
        public_key_pem: pubPem,
        private_pem: privPem,
      });

      $("createAddress").value = address;
      $("createPub").value = pubPem;
      $("createOut").classList.remove("hidden");

      addDebug("[create] wallet created: " + address);
    }catch(e){
      toast("createMsg","Create error: " + e.message);
      addDebug("[create] " + e.stack);
    }
  };

  $("btnRegister").onclick = async ()=>{
    const meta = loadWallet();
    if(!meta) return toast("createMsg","Нема локального гаманця");
    try{
      await apiRegisterWallet(meta.address, meta.public_key_pem, null);
      toast("createMsg","Зареєстровано ✅");
    }catch(e){
      toast("createMsg","Register error: " + e.message);
      addDebug("[register] " + e.message);
    }
  };

  $("btnCopyAddr").onclick = async ()=>{
    const meta = loadWallet();
    if(!meta) return;
    await navigator.clipboard.writeText(meta.address);
    alert("Скопійовано ✅");
  };

  // import
  $("btnLoadLocal").onclick = ()=>{
    const meta = loadWallet();
    if(!meta) return toast("importMsg","Локального гаманця нема");
    toast("importMsg","Локальний гаманець знайдено ✅");
  };

  $("btnDoImport").onclick = async ()=>{
    try{
      const priv = $("importPriv").value.trim();
      if(!priv) return toast("importMsg","Встав private key PEM");
      await importPrivatePem(priv); // validate

      // якщо нема pub — MVP не зможе (поки)
      const existing = loadWallet();
      if(!existing?.public_key_pem){
        return toast("importMsg","MVP: потрібен public key (створи гаманець тут хоча б 1 раз)");
      }

      const address = await addressFromPublicPem(existing.public_key_pem);
      saveWallet({ address, public_key_pem: existing.public_key_pem, private_pem: priv });

      toast("importMsg","Імпорт успішний ✅");
      await refreshWalletUI();
      show("Wallet");
    }catch(e){
      toast("importMsg","Import error: " + e.message);
      addDebug("[import] " + e.message);
    }
  };

  // wallet
  $("btnRefresh").onclick = refreshWalletUI;
  $("btnShowKeys").onclick = ()=> $("pubModal").classList.remove("hidden");
  $("btnCloseModal").onclick = ()=> $("pubModal").classList.add("hidden");

  // send
  $("btnDoSend").onclick = async ()=>{
    const meta = loadWallet();
    if(!meta) return toast("sendMsg","Нема гаманця");

    try{
      const to = $("sendTo").value.trim();
      const amt = Number($("sendAmt").value.trim() || "0");
      const memo = $("sendMemo").value.trim() || null;

      if(!to) return toast("sendMsg","Вкажи To address");
      if(!Number.isFinite(amt) || amt <= 0) return toast("sendMsg","Amount > 0");

      const privKey = await importPrivatePem(meta.private_pem);
      const nonce = getNextNonce();
      const msg = `${meta.address}:${to}:${amt}:${nonce}`;
      const sigB64 = await signMessage(privKey, new TextEncoder().encode(msg));

      const payload = {
        from_address: meta.address,
        to_address: to,
        amount: amt,
        memo,
        signature: sigB64,
        nonce,
        public_key: meta.public_key_pem
      };

      const res = await apiSendTx(payload);
      toast("sendMsg", "Відправлено ✅ tx_id=" + res.tx_id);
      await refreshWalletUI();
    }catch(e){
      toast("sendMsg","Send error: " + e.message);
      addDebug("[send] " + e.message);
    }
  };

  // receive
  $("btnRegenQR").onclick = ()=>{
    const meta = loadWallet();
    if(!meta) return;
    renderQR(meta.address);
  };

  // scan
  $("btnStopScan").onclick = stopScan;

  // API badge
  const ok = await apiPing();
  $("apiBadge").textContent = ok ? "API: онлайн ✅" : "API: офлайн ❌";

  // init view
  const meta = loadWallet();
  if(meta){
    show("Wallet");
    await refreshWalletUI();
    renderQR(meta.address);
  }else{
    show("Welcome");
  }

  addDebug("boot() done ✅");
}

window.addEventListener("error", (e)=>{
  try{
    $("debugBox").classList.remove("hidden");
    addDebug("[window.error] " + (e?.message || "unknown"));
  }catch{}
});

boot();
