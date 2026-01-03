console.log("APP JS LOADED");

// =====================
// CONFIG
// =====================
const API_BASE = "https://setwallet.onrender.com"; // Render URL

// Local storage keys
const LS_WALLET = "setwallet_wallet_v1";
const LS_NONCE  = "setwallet_last_nonce_v1";

// =====================
// DOM helpers (SAFE)
// =====================
const $ = (id) => document.getElementById(id);

function setText(id, txt) {
  const el = $(id);
  if (el) el.textContent = txt;
}

function setValue(id, val) {
  const el = $(id);
  if (el) el.value = val;
}

function onClick(id, fn) {
  const el = $(id);
  if (el) el.onclick = fn;
}

function hasEl(id) {
  return !!$(id);
}

// =====================
// UI
// =====================
function loadWalletMeta(){
  try{
    const raw = localStorage.getItem(LS_WALLET);
    if(!raw) return null;
    const w = JSON.parse(raw);
    return w?.address ? w : null;
  }catch{ return null; }
}

function show(view) {
  const views = ["Welcome","Create","Import","Wallet","Send","Receive","Scan"];

  // hide all safely
  for (const v of views) {
    const el = $("view" + v);
    if (el) el.classList.add("hidden");
  }

  // show target safely
  const target = $("view" + view);
  if (target) target.classList.remove("hidden");

  // logout visibility
  const hasWallet = !!loadWalletMeta();
  const logoutBtn = $("btnLogout");
  if (logoutBtn) logoutBtn.classList.toggle("hidden", !hasWallet);
}

function toast(el, msg) {
  if (!el) return;
  el.textContent = msg;
  el.classList.remove("hidden");
  setTimeout(()=> el.classList.add("hidden"), 6000);
}

// ✅ nav expects LOWERCASE
function nav(where){
  const w = (where || "").toLowerCase();

  if(w === "welcome") return show("Welcome");
  if(w === "create")  return show("Create");
  if(w === "import")  return show("Import");
  if(w === "wallet")  return show("Wallet");
  if(w === "send")    return show("Send");
  if(w === "receive") return show("Receive");
  if(w === "scan")    return show("Scan");
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

async function signMessage(privKey, messageBytes){
  const sig = await crypto.subtle.sign(
    { name:"ECDSA", hash:"SHA-256" },
    privKey,
    messageBytes
  );
  return bufToB64(sig);
}

// =====================
// Local storage
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
// QR (SAFE: if QRCode lib missing -> message)
// =====================
let qrObj = null;

function makeQrPayload(address){
  return JSON.stringify({ v:1, type:"setwallet_transfer", to: address });
}

function renderQR(address){
  const payload = makeQrPayload(address);

  if (hasEl("qrPayload")) setValue("qrPayload", payload);
  const qrEl = $("qr");
  if (!qrEl) return;

  qrEl.innerHTML = "";

  if (typeof QRCode === "undefined") {
    qrEl.innerHTML = "<div style='opacity:.8'>QR lib не підключена (QRCode)</div>";
    return;
  }

  qrObj = new QRCode(qrEl, { text: payload, width: 220, height: 220 });
}

// =====================
// Scanner (SAFE: if html5-qrcode missing)
// =====================
let qrScanner = null;

async function startScan(){
  const msgEl = $("scanMsg");
  if (msgEl) msgEl.classList.add("hidden");

  if (typeof Html5Qrcode === "undefined") {
    toast(msgEl, "Сканер не підключений (html5-qrcode)");
    return;
  }

  if(qrScanner) return;

  qrScanner = new Html5Qrcode("scanner");
  const devices = await Html5Qrcode.getCameras();
  const cameraId = devices?.[0]?.id;

  if(!cameraId) {
    toast(msgEl, "Камеру не знайдено");
    return;
  }

  await qrScanner.start(
    cameraId,
    { fps: 10, qrbox: { width: 250, height: 250 } },
    (decodedText) => {
      try{
        const data = JSON.parse(decodedText);
        if(data?.to){
          if (hasEl("sendTo")) setValue("sendTo", data.to);
          if (data.amount && hasEl("sendAmt")) setValue("sendAmt", String(data.amount));

          toast(msgEl, "QR зчитано ✅ Переходимо в Send");
          stopScan();
          nav("send");
        } else {
          toast(msgEl, "QR не схожий на SETWALLET");
        }
      }catch{
        toast(msgEl, "Не вдалося прочитати QR (не JSON)");
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

  setText("walletAddr", meta.address);
  if (hasEl("walletPub")) setValue("walletPub", meta.public_key_pem);

  return meta;
}

async function refreshBalance(){
  const meta = await ensureWalletLoaded();
  if(!meta) return;

  try{
    const bal = await apiGetBalance(meta.address);
    setText("walletBal", String(bal));
  }catch(e){
    setText("walletBal", "0");
    alert("Balance error: " + e.message);
  }
}

// =====================
// Init UI events (SAFE)
// =====================
document.addEventListener("click", (e)=>{
  const btn = e.target.closest("[data-nav]");
  if(!btn) return;

  const to = (btn.getAttribute("data-nav") || "").toLowerCase();

  if(to === "scan") startScan();
  else stopScan();

  // ✅ FIX: call nav(to) directly (lowercase)
  nav(to);
});

// Buttons
onClick("btnCreate", ()=> nav("create"));
onClick("btnImport", ()=> nav("import"));

onClick("btnLogout", ()=>{
  stopScan();
  clearWallet();
  nav("welcome");
});

onClick("btnCopyAddr", async ()=>{
  const meta = loadWalletMeta();
  if(!meta) return;
  await navigator.clipboard.writeText(meta.address);
  alert("Скопійовано ✅");
});

onClick("btnRefresh", refreshBalance);

onClick("btnShowKeys", ()=> {
  const m = $("pubModal");
  if (m) m.classList.remove("hidden");
});
onClick("btnCloseModal", ()=> {
  const m = $("pubModal");
  if (m) m.classList.add("hidden");
});

onClick("btnRegenQR", async ()=>{
  const meta = await ensureWalletLoaded();
  if(!meta) return;
  renderQR(meta.address);
});

// Create
onClick("btnDoCreate", async ()=>{
  const out = $("createOut");
  if (out) out.classList.add("hidden");

  const pass = ( $("createPass")?.value || "" ).trim();

  const kp = await generateKeypair();
  const pubPem = await exportPublicPem(kp.publicKey);
  const privPem = await exportPrivatePem(kp.privateKey);
  const address = await addressFromPublicPem(pubPem);

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

  if (hasEl("createAddress")) setValue("createAddress", address);
  if (hasEl("createPub")) setValue("createPub", pubPem);

  if (out) out.classList.remove("hidden");
});

onClick("btnRegister", async ()=>{
  const meta = loadWalletMeta();
  if(!meta) return;

  try{
    await apiRegisterWallet(
      meta.address,
      meta.public_key_pem,
      meta.encrypted ? JSON.stringify(meta.vault) : null
    );
    alert("Зареєстровано ✅");
  }catch(e){
    alert("Register error: " + e.message);
  }
});

onClick("btnGoWallet1", async ()=>{
  nav("wallet");
  await refreshBalance();
  const meta = loadWalletMeta();
  if(meta) renderQR(meta.address);
});

// Import
onClick("btnLoadLocal", async ()=>{
  const meta = loadWalletMeta();
  if(!meta){ toast($("importMsg"), "Локального гаманця не знайдено"); return; }
  toast($("importMsg"), "Локальний гаманець знайдено ✅ Натисни Імпортувати або просто відкрий Wallet");
});

onClick("btnDoImport", async ()=>{
  const pass = ( $("importPass")?.value || "" ).trim();
  const privPemInput = ( $("importPriv")?.value || "" ).trim();

  try{
    let privPem = privPemInput;
    let meta = loadWalletMeta();

    if(!privPem){
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
    await importPrivatePem(privPem);

    if(!meta?.public_key_pem){
      throw new Error("Для MVP потрібен public key PEM (створюй гаманець тут або збережи public key)");
    }

    const address = await addressFromPublicPem(meta.public_key_pem);

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
    renderQR(address);
  }catch(e){
    toast($("importMsg"), "Import error: " + e.message);
  }
});

// Send
onClick("btnDoSend", async ()=>{
  const meta = loadWalletMeta();
  if(!meta) return;

  const to = ( $("sendTo")?.value || "" ).trim();
  const amt = Number(( $("sendAmt")?.value || "0" ).trim());
  const memo = ( $("sendMemo")?.value || "" ).trim() || null;

  if(!to) return toast($("sendMsg"), "Вкажи To address");
  if(!Number.isFinite(amt) || amt <= 0) return toast($("sendMsg"), "Вкажи Amount > 0");

  try{
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

    if (hasEl("sendMemo")) setValue("sendMemo", "");
    await refreshBalance();
  }catch(e){
    toast($("sendMsg"), "Send error: " + e.message);
  }
});

// =====================
// Boot
// =====================
(async function boot(){
  const ok = await apiPing();
  setText("apiStatus", ok ? "онлайн ✅" : "не відповідає ❌");

  const meta = loadWalletMeta();
  if(meta){
    nav("wallet");
    await refreshBalance();
    renderQR(meta.address);
  } else {
    nav("welcome");
  }
})();
