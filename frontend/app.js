console.log("APP JS LOADED");

// =====================
// CONFIG
// =====================
const API_BASE = "https://setwallet.onrender.com"; // <-- ЗАМІНИ, якщо інший Render URL

// Local storage keys
const LS_WALLET = "setwallet_wallet_v1";
const LS_NONCE  = "setwallet_last_nonce_v1";

// =====================
// UI helpers
// =====================
const $ = (id) => document.getElementById(id);

function show(view) {
  const views = ["Welcome","Create","Import","Wallet","Send","Receive","Scan"];
  for (const v of views) $("view"+v).classList.add("hidden");
  $("view"+view).classList.remove("hidden");

  // logout button
  const hasWallet = !!loadWalletMeta();
  $("btnLogout").classList.toggle("hidden", !hasWallet);
}

function toast(el, msg) {
  el.textContent = msg;
  el.classList.remove("hidden");
  setTimeout(()=> el.classList.add("hidden"), 6000);
}

function nav(where){
  if(where === "welcome") show("Welcome");
  if(where === "create") show("Create");
  if(where === "import") show("Import");
  if(where === "wallet") show("Wallet");
  if(where === "send") show("Send");
  if(where === "receive") show("Receive");
  if(where === "scan") show("Scan");
}

// =====================
// API
// =====================
async function apiPing(){
  try{
    const r = await fetch(API_BASE + "/openapi.json");
    return r.ok;
  }catch{ return false; }
}

async function apiRegisterWallet(address, public_key_pem, vault_encrypted=null){
  const r = await fetch(API_BASE + "/wallets/register", {
    method:"POST",
    headers:{ "Content-Type":"application/json" },
    body: JSON.stringify({ address, public_key: public_key_pem, vault_encrypted })
  });
  const j = await r.json().catch(()=> ({}));
  if(!r.ok) throw new Error(j.detail || "Register failed");
  return j;
}

async function apiGetBalance(address){
  const r = await fetch(API_BASE + `/wallets/${encodeURIComponent(address)}/balance`);
  const j = await r.json().catch(()=> ({}));
  if(!r.ok) throw new Error(j.detail || "Balance failed");
  return j.balance ?? 0;
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

// =====================
// Crypto (WebCrypto ECDSA P-256 + SHA-256)
// =====================
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

function pemToDer(pem){
  const lines = pem.trim().split("\n");
  const b64 = lines.filter(l=>!l.startsWith("-----")).join("");
  return b64ToBuf(b64);
}

async function importPrivatePem(pem){
  const der = pemToDer(pem);
  return crypto.subtle.importKey(
    "pkcs8",
    der,
    { name:"ECDSA", namedCurve:"P-256" },
    true,
    ["sign"]
  );
}

async function importPublicPem(pem){
  const der = pemToDer(pem);
  return crypto.subtle.importKey(
    "spki",
    der,
    { name:"ECDSA", namedCurve:"P-256" },
    true,
    ["verify"]
  );
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
  // address = "SET" + first 20 bytes of SHA256(publicPem)
  const enc = new TextEncoder();
  const hash = await sha256(enc.encode(pubPem));
  const hex = ab2hex(hash);
  return "SET" + hex.slice(0, 40); // 20 bytes = 40 hex
}

async function signMessage(privKey, messageBytes){
  const sig = await crypto.subtle.sign(
    { name:"ECDSA", hash:"SHA-256" },
    privKey,
    messageBytes
  );
  return bufToB64(sig);
}

// =====================
// Local wallet storage (MVP)
// - якщо є пароль: шифруємо private PEM AES-GCM (PBKDF2)
// - якщо нема: зберігаємо plaintext (тільки для MVP)
// =====================
async function deriveAesKey(pass, saltB64){
  const salt = saltB64 ? b64ToBuf(saltB64) : crypto.getRandomValues(new Uint8Array(16)).buffer;
  const baseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(pass),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  const aesKey = await crypto.subtle.deriveKey(
    { name:"PBKDF2", salt, iterations: 120000, hash:"SHA-256" },
    baseKey,
    { name:"AES-GCM", length: 256 },
    false,
    ["encrypt","decrypt"]
  );
  return { aesKey, saltB64: bufToB64(salt) };
}

async function encryptText(pass, plaintext){
  const { aesKey, saltB64 } = await deriveAesKey(pass);
  const iv = crypto.getRandomValues(new Uint8Array(12)).buffer;
  const ct = await crypto.subtle.encrypt(
    { name:"AES-GCM", iv },
    aesKey,
    new TextEncoder().encode(plaintext)
  );
  return { saltB64, ivB64: bufToB64(iv), ctB64: bufToB64(ct) };
}

async function decryptText(pass, blob){
  const { aesKey } = await deriveAesKey(pass, blob.saltB64);
  const pt = await crypto.subtle.decrypt(
    { name:"AES-GCM", iv: b64ToBuf(blob.ivB64) },
    aesKey,
    b64ToBuf(blob.ctB64)
  );
  return new TextDecoder().decode(pt);
}

function saveWallet(payload){
  localStorage.setItem(LS_WALLET, JSON.stringify(payload));
}

function loadWalletMeta(){
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

// =====================
// QR
// =====================
let qrObj = null;
function makeQrPayload(address){
  return JSON.stringify({ v:1, type:"setwallet_transfer", to: address });
}
function renderQR(address){
  const payload = makeQrPayload(address);
  $("qrPayload").value = payload;
  $("qr").innerHTML = "";
  qrObj = new QRCode($("qr"), {
    text: payload,
    width: 220,
    height: 220
  });
}

// =====================
// Scanner
// =====================
let qrScanner = null;
async function startScan(){
  $("scanMsg").classList.add("hidden");
  if(qrScanner) return;

  qrScanner = new Html5Qrcode("scanner");
  const devices = await Html5Qrcode.getCameras();
  const cameraId = devices?.[0]?.id;
  if(!cameraId) {
    toast($("scanMsg"), "Камеру не знайдено");
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
          if(data.amount) $("sendAmt").value = String(data.amount);
          toast($("scanMsg"), "QR зчитано ✅ Переходимо в Send");
          stopScan();
          nav("send");
        } else {
          toast($("scanMsg"), "QR не схожий на SETWALLET");
        }
      }catch{
        toast($("scanMsg"), "Не вдалося прочитати QR (не JSON)");
      }
    },
    () => {}
  );
}

async function stopScan(){
  if(!qrScanner) return;
  try{ await qrScanner.stop(); }catch{}
  try{ await qrScanner.clear(); }catch{}
  qrScanner = null;
}

// =====================
// App flow
// =====================
async function ensureWalletLoaded(){
  const meta = loadWalletMeta();
  if(!meta) { nav("welcome"); return null; }
  $("walletAddr").textContent = meta.address;
  $("walletPub").value = meta.public_key_pem;
  return meta;
}

async function refreshBalance(){
  const meta = await ensureWalletLoaded();
  if(!meta) return;
  try{
    const bal = await apiGetBalance(meta.address);
    $("walletBal").textContent = String(bal);
  }catch(e){
    $("walletBal").textContent = "0";
    alert("Balance error: " + e.message);
  }
}

// =====================
// Init UI
// =====================
document.addEventListener("click", (e)=>{
  const btn = e.target.closest("[data-nav]");
  if(btn){
    const to = btn.getAttribute("data-nav");
    if(to === "scan") startScan();
    if(to !== "scan") stopScan();
    nav(to[0].toUpperCase()+to.slice(1));
  }
});

// Buttons
$("btnCreate").onclick = ()=> nav("create");
$("btnImport").onclick = ()=> nav("import");

$("btnLogout").onclick = ()=>{
  stopScan();
  clearWallet();
  nav("welcome");
};

$("btnCopyAddr").onclick = async ()=>{
  const meta = loadWalletMeta();
  if(!meta) return;
  await navigator.clipboard.writeText(meta.address);
  alert("Скопійовано ✅");
};

$("btnRefresh").onclick = refreshBalance;

$("btnShowKeys").onclick = ()=>{
  $("pubModal").classList.remove("hidden");
};
$("btnCloseModal").onclick = ()=>{
  $("pubModal").classList.add("hidden");
};

$("btnRegenQR").onclick = async ()=>{
  const meta = await ensureWalletLoaded();
  if(!meta) return;
  renderQR(meta.address);
};

// Create
$("btnDoCreate").onclick = async ()=>{
  $("createOut").classList.add("hidden");
  const pass = $("createPass").value.trim();

  const kp = await generateKeypair();
  const pubPem = await exportPublicPem(kp.publicKey);
  const privPem = await exportPrivatePem(kp.privateKey);
  const address = await addressFromPublicPem(pubPem);

  // store
  let stored = { address, public_key_pem: pubPem, encrypted: false, vault: null };

  if(pass){
    const vault = await encryptText(pass, privPem);
    stored.encrypted = true;
    stored.vault = vault;
  } else {
    stored.encrypted = false;
    stored.private_pem = privPem; // MVP only
  }

  saveWallet(stored);

  $("createAddress").value = address;
  $("createPub").value = pubPem;
  $("createOut").classList.remove("hidden");
};

$("btnRegister").onclick = async ()=>{
  const meta = loadWalletMeta();
  if(!meta) return;

  try{
    await apiRegisterWallet(meta.address, meta.public_key_pem, meta.encrypted ? JSON.stringify(meta.vault) : null);
    alert("Зареєстровано ✅");
  }catch(e){
    alert("Register error: " + e.message);
  }
};

$("btnGoWallet1").onclick = async ()=>{
  nav("wallet");
  await refreshBalance();
};

// Import
$("btnLoadLocal").onclick = async ()=>{
  const meta = loadWalletMeta();
  if(!meta){ toast($("importMsg"), "Локального гаманця не знайдено"); return; }
  toast($("importMsg"), "Локальний гаманець знайдено ✅ Натисни Імпортувати або просто відкрий Wallet");
};

$("btnDoImport").onclick = async ()=>{
  const pass = $("importPass").value.trim();
  const privPemInput = $("importPriv").value.trim();

  try{
    let privPem = privPemInput;
    let meta = loadWalletMeta();

    if(!privPem){
      // try decrypt from local vault
      if(!meta) throw new Error("Немає локального vault і не вставлений private key");
      if(meta.encrypted){
        if(!pass) throw new Error("Потрібен пароль для розшифрування");
        privPem = await decryptText(pass, meta.vault);
      } else if(meta.private_pem){
        privPem = meta.private_pem;
      } else {
        throw new Error("Немає private key у локальному сховищі");
      }
    }

    // validate import by importing key
    const privKey = await importPrivatePem(privPem);

    // if user pasted private key, we need public key too
    // for MVP: we keep existing public key if exists, else fail
    if(!meta?.public_key_pem){
      throw new Error("Для MVP потрібен public key PEM (створюй гаманець тут або збережи public key)");
    }

    // derive address again from stored pub
    const address = await addressFromPublicPem(meta.public_key_pem);

    // store (re-encrypt if password provided)
    let stored = { address, public_key_pem: meta.public_key_pem, encrypted:false, vault:null };

    if(pass){
      const vault = await encryptText(pass, privPem);
      stored.encrypted = true;
      stored.vault = vault;
    } else {
      stored.private_pem = privPem;
    }

    saveWallet(stored);
    toast($("importMsg"), "Імпорт успішний ✅");
    nav("wallet");
    await refreshBalance();
  }catch(e){
    toast($("importMsg"), "Import error: " + e.message);
  }
};

// Send
$("btnDoSend").onclick = async ()=>{
  const meta = loadWalletMeta();
  if(!meta) return;

  const to = $("sendTo").value.trim();
  const amt = Number($("sendAmt").value.trim() || "0");
  const memo = $("sendMemo").value.trim() || null;

  if(!to) return toast($("sendMsg"), "Вкажи To address");
  if(!Number.isFinite(amt) || amt <= 0) return toast($("sendMsg"), "Вкажи Amount > 0");

  try{
    // load private key
    let privPem = null;
    if(meta.encrypted){
      const pass = prompt("Введи пароль для підпису транзакції:");
      if(!pass) throw new Error("Пароль не введено");
      privPem = await decryptText(pass, meta.vault);
    } else {
      if(!meta.private_pem) throw new Error("Нема private key (імпортуй або створи з паролем)");
      privPem = meta.private_pem;
    }

    const privKey = await importPrivatePem(privPem);
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
    toast($("sendMsg"), `Відправлено ✅ tx_id=${res.tx_id}`);
    $("sendMemo").value = "";
    await refreshBalance();
  }catch(e){
    toast($("sendMsg"), "Send error: " + e.message);
  }
};

// =====================
// Boot
// =====================
(async function boot(){
  // API status
  const ok = await apiPing();
  $("apiStatus").textContent = ok ? "онлайн ✅" : "не відповідає ❌";

  // initial view
  const meta = loadWalletMeta();
  if(meta){
    nav("wallet");
    await refreshBalance();
    renderQR(meta.address);
  } else {
    nav("welcome");
  }
})();
