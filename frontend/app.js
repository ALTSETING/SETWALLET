console.log("SETWALLET UI LOADED");

// =====================
// CONFIG
// =====================
const API_BASE_STORAGE_KEY = "setwallet_api_base";
const DEFAULT_API_BASE = "https://setwallet.onrender.com";

const removeLoader = () => {
  const loader = document.getElementById("appLoader");
  if(!loader || loader.classList.contains("done")) return;
  loader.classList.add("done");
  setTimeout(() => loader.remove(), 700);
};

document.addEventListener("DOMContentLoaded", () => {
  setTimeout(removeLoader, 1200);
});

window.addEventListener("load", removeLoader);

function normalizeApiBase(url){
  if(!url) return "";
  return url.replace(/\/+$/g, "");
}

function resolveApiBase(){
  const params = new URLSearchParams(window.location.search);
  const paramBase = params.get("api");
  if(paramBase){
    const normalized = normalizeApiBase(paramBase);
    localStorage.setItem(API_BASE_STORAGE_KEY, normalized);
    return normalized;
  }

  const stored = localStorage.getItem(API_BASE_STORAGE_KEY);
  if(stored) return normalizeApiBase(stored);

  if(window.SETWALLET_API_BASE){
    return normalizeApiBase(window.SETWALLET_API_BASE);
  }

  const host = window.location.hostname;
  if(host === "localhost" || host === "127.0.0.1"){
    return "http://localhost:8000";
  }

  if(window.location.origin && window.location.origin !== "null"){
     const origin = normalizeApiBase(window.location.origin);
    if(origin === DEFAULT_API_BASE){
      return origin;
    }
  }

   return DEFAULT_API_BASE;
}

let API_BASE = resolveApiBase();

// Local storage keys
const LS_WALLET = "setwallet_wallet_v2";
const LS_NONCE  = "setwallet_last_nonce_v2";

// =====================
// DOM helpers
// =====================
const $ = (id) => document.getElementById(id);

function safeEl(id){
  const el = $(id);
  return el || null;
}

function show(view){
  const views = ["Welcome","Create","Import","Wallet","Send","Receive","History","Settings"];
  for (const v of views){
    const el = safeEl("view"+v);
    if (el) el.classList.add("hidden");
  }
  const target = safeEl("view"+view);
  if (target) target.classList.remove("hidden");

  // bottom nav active
  document.querySelectorAll(".bottomNav .navBtn").forEach(b => b.classList.remove("active"));
  document.querySelectorAll(`.bottomNav .navBtn[data-nav="${view.toLowerCase()}"]`).forEach(b => b.classList.add("active"));
}

function toast(id, msg){
  const el = safeEl(id);
  if(!el) return;
  el.textContent = msg;
  el.classList.remove("hidden");
  setTimeout(()=> el.classList.add("hidden"), 5500);
}

function updateApiStatus(ok){
  const apiEl = safeEl("apiStatus");
  if(apiEl) apiEl.textContent = ok ? "онлайн ✅" : "не відповідає ❌";
}

async function pingAndUpdateStatus(){
  const ok = await apiPing();
  updateApiStatus(ok);
}

function updateApiBaseInput(){
  const input = safeEl("apiBaseInput");
  if(input) input.value = API_BASE;
}

function shortAddr(a){
  if(!a) return "—";
  return a.length > 18 ? a.slice(0,8) + "…" + a.slice(-6) : a;
}

function fmtTime(iso){
  if(!iso) return "";
  const d = new Date(iso);
  return d.toLocaleString();
}

// =====================
// API
// =====================
async function apiPing(){
  try{
    const r = await fetch(API_BASE + "/health");
    return r.ok;
  }catch{ return false; }
}

async function apiRegisterWallet(address, public_key){
  const r = await fetch(API_BASE + "/wallets/register", {
    method:"POST",
    headers:{ "Content-Type":"application/json" },
    body: JSON.stringify({ address, public_key })
  });
  const j = await r.json().catch(()=> ({}));
  if(!r.ok) throw new Error(j.detail || "Register failed");
  return j;
}

  async function registerWalletIfPossible(wallet, toastId, options = {}){
  if(!wallet?.address || !wallet?.public_key_pem) return false;
  try{
    await apiRegisterWallet(wallet.address, wallet.public_key_pem);
    if(toastId) toast(toastId, "Гаманець зареєстровано ✅");
    return true;
  }catch(e){
    if(toastId) toast(toastId, "Register error: " + e.message);
    if(options.throwOnError) throw e;
    return false;
  }
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

async function apiHistory(address, limit=50){
  const r = await fetch(API_BASE + `/tx/history/${encodeURIComponent(address)}?limit=${limit}`);
  const j = await r.json().catch(()=> ({}));
  if(!r.ok) throw new Error(j.detail || "History failed");
  return j.items || [];
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
  // MUST match backend: "SET" + first 20 bytes of SHA256(pubPem)
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
// Local wallet storage (MVP)
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

// =====================
// QR
// =====================
let qrObj = null;
function makeQrPayload(address){
  return JSON.stringify({ v:1, type:"setwallet_transfer", to: address });
}
function renderQR(address){
  const payload = makeQrPayload(address);
  const qp = safeEl("qrPayload");
  if (qp) qp.value = payload;

  const q = safeEl("qr");
  if(!q) return;

  q.innerHTML = "";
  qrObj = new QRCode(q, { text: payload, width: 220, height: 220 });
}

// =====================
// UI bind
// =====================
function bindNav(){
  document.addEventListener("click", (e)=>{
    const navBtn = e.target.closest("[data-nav]");
    if(!navBtn) return;
    const to = navBtn.getAttribute("data-nav");
    if(!to) return;

    // normalized views
    const map = {
      welcome:"Welcome",
      create:"Create",
      import:"Import",
      wallet:"Wallet",
      send:"Send",
      receive:"Receive",
      history:"History",
      settings:"Settings"
    };
    const view = map[to.toLowerCase()];
    if(view) show(view);
  });

  // bottom nav
  document.querySelectorAll(".bottomNav .navBtn").forEach(btn=>{
    btn.addEventListener("click", ()=>{
      const to = btn.getAttribute("data-nav");
      const map = { wallet:"Wallet", send:"Send", receive:"Receive", history:"History", settings:"Settings" };
      const v = map[to];
      if(v) show(v);
    });
  });
}

async function refreshBalanceUI(){
  const w = loadWallet();
  if(!w) return;

  const sk = safeEl("balSkeleton");
  const real = safeEl("balReal");
  if(sk) sk.classList.remove("hidden");
  if(real) real.classList.add("hidden");

  try{
    const bal = await apiGetBalance(w.address);
    const wb = safeEl("walletBal");
    if(wb) wb.textContent = String(bal);
  }catch(e){
    toast("dashMsg", "Balance error: " + e.message);
  }finally{
    if(sk) sk.classList.add("hidden");
    if(real) real.classList.remove("hidden");
  }
}

async function refreshHistoryUI(){
  const w = loadWallet();
  if(!w) return;

  const sk = safeEl("histSkeleton");
  const list = safeEl("histList");
  if(sk) sk.classList.remove("hidden");
  if(list) { list.classList.add("hidden"); list.innerHTML=""; }

  try{
    const items = await apiHistory(w.address, 60);
    if(!list) return;

    if(items.length === 0){
      list.innerHTML = `<div class="muted">Транзакцій поки немає.</div>`;
    } else {
      list.innerHTML = items.map(it=>{
        const incoming = it.to_address === w.address;
        const title = incoming ? "IN" : "OUT";
        const sign = incoming ? "+" : "-";
        const peer = incoming ? it.from_address : it.to_address;

        return `
          <div class="histItem">
            <div class="hL">
              <div class="hT">${title} • ${shortAddr(peer)}</div>
              <div class="hS">tx: ${it.tx_id} • nonce: ${it.nonce}${it.memo ? ` • memo: ${it.memo}` : ""}</div>
            </div>
            <div class="hR">
              <div class="hAmt">${sign}${it.amount} ALT</div>
              <div class="hTime">${fmtTime(it.created_at)}</div>
            </div>
          </div>
        `;
      }).join("");
    }

    list.classList.remove("hidden");
  }catch(e){
    toast("histMsg", "History error: " + e.message);
  }finally{
    if(sk) sk.classList.add("hidden");
  }
}

// =====================
// Actions
// =====================
function bindActions(){
  // Quick settings button
  const qs = safeEl("btnQuickSettings");
  if(qs) qs.onclick = ()=> show("Settings");

  // Create / Import nav
  const bc = safeEl("btnCreate");
  if(bc) bc.onclick = ()=> show("Create");
  const bi = safeEl("btnImport");
  if(bi) bi.onclick = ()=> show("Import");

  // Create flow
  const btnDoCreate = safeEl("btnDoCreate");
  if(btnDoCreate) btnDoCreate.onclick = async ()=>{
    const pass = (safeEl("createPass")?.value || "").trim();

    const kp = await generateKeypair();
    const pubPem = await exportPublicPem(kp.publicKey);
    const privPem = await exportPrivatePem(kp.privateKey);
    const address = await addressFromPublicPem(pubPem);

    let stored = { address, public_key_pem: pubPem, encrypted: false, vault: null };

    if(pass){
      const vault = await encryptText(pass, privPem);
      stored.encrypted = true;
      stored.vault = vault;
    }else{
      stored.private_pem = privPem; // MVP only
    }

    saveWallet(stored);

    if(safeEl("createAddress")) safeEl("createAddress").value = address;
    if(safeEl("createPub")) safeEl("createPub").value = pubPem;

    safeEl("createOut")?.classList.remove("hidden");
    toast("createMsg", "Гаманець створено ✅");
    await registerWalletIfPossible(stored, "createMsg");
  };

  // Copy created address
  const cpy = safeEl("btnCopyCreateAddr");
  if(cpy) cpy.onclick = async ()=>{
    const v = safeEl("createAddress")?.value || "";
    if(!v) return;
    await navigator.clipboard.writeText(v);
    toast("createMsg", "Скопійовано ✅");
  };

  // Register
  const reg = safeEl("btnRegister");
  if(reg) reg.onclick = async ()=>{
    const w = loadWallet();
    if(!w) return toast("createMsg", "Нема локального гаманця");
    await registerWalletIfPossible(w, "createMsg");
  };

  const regDash = safeEl("btnRegisterWallet");
  if(regDash) regDash.onclick = async ()=>{
    const w = loadWallet();
    if(!w) return toast("dashMsg", "Нема локального гаманця");
    await registerWalletIfPossible(w, "dashMsg");
  };

  // Go wallet
  const goW = safeEl("btnGoWalletFromCreate");
  if(goW) goW.onclick = async ()=>{
    show("Wallet");
    await onEnterWallet();
  };

  // Import JSON
  const btnImportJson = safeEl("btnImportJson");
  const importFile = safeEl("importFile");
  if(btnImportJson && importFile){
    btnImportJson.onclick = ()=> importFile.click();
    importFile.onchange = async ()=>{
      const file = importFile.files?.[0];
      if(!file) return;
      const text = await file.text();
      let obj;
      try{ obj = JSON.parse(text); }catch{ return toast("importMsg", "Bad JSON"); }

      try{
        // expected backup format
        const pass = (safeEl("importPass")?.value || "").trim();
        const address = obj.address;
        const public_key_pem = obj.public_key_pem;
        let privPem;

        if(obj.encrypted){
          if(!pass) throw new Error("Потрібен пароль для розшифрування backup");
          privPem = await decryptText(pass, obj.vault);
        }else{
          privPem = obj.private_pem;
        }
        if(!address || !public_key_pem || !privPem) throw new Error("Backup неповний");

        // store as encrypted if pass provided, else plaintext
        let stored = { address, public_key_pem, encrypted:false, vault:null };
        if(pass){
          const vault = await encryptText(pass, privPem);
          stored.encrypted = true;
          stored.vault = vault;
        }else{
          stored.private_pem = privPem;
        }

        saveWallet(stored);
        toast("importMsg", "Імпорт успішний ✅");
        await registerWalletIfPossible(stored, "importMsg");
        show("Wallet");
        await onEnterWallet();
      }catch(e){
        toast("importMsg", "Import error: " + e.message);
      }
    };
  }

  // Load local
  const btnLoadLocal = safeEl("btnLoadLocal");
  if(btnLoadLocal) btnLoadLocal.onclick = ()=>{
    const w = loadWallet();
    if(w) toast("importMsg", "Локальний гаманець знайдено ✅ Просто відкрий Wallet");
    else toast("importMsg", "Локального гаманця немає");
  };

  // PEM Import (emergency)
  const btnDoImport = safeEl("btnDoImport");
  if(btnDoImport) btnDoImport.onclick = async ()=>{
    const w0 = loadWallet();
    const pass = (safeEl("importPass")?.value || "").trim();
    const privPemInput = (safeEl("importPriv")?.value || "").trim();

    try{
      if(!w0?.public_key_pem){
        throw new Error("Нема public key. Для MVP імпорт PEM працює тільки якщо цей браузер вже створював wallet.");
      }
      if(!privPemInput) throw new Error("Встав private key PEM або імпортуй backup JSON");

      const address = await addressFromPublicPem(w0.public_key_pem);

      let stored = { address, public_key_pem: w0.public_key_pem, encrypted:false, vault:null };
      if(pass){
        const vault = await encryptText(pass, privPemInput);
        stored.encrypted = true;
        stored.vault = vault;
      }else{
        stored.private_pem = privPemInput;
      }

      saveWallet(stored);
      toast("importMsg", "PEM імпорт OK ✅");
      await registerWalletIfPossible(stored, "importMsg");
      show("Wallet");
      await onEnterWallet();
    }catch(e){
      toast("importMsg", "Import error: " + e.message);
    }
  };

  // Copy addr
  const btnCopyAddr = safeEl("btnCopyAddr");
  if(btnCopyAddr) btnCopyAddr.onclick = async ()=>{
    const w = loadWallet();
    if(!w) return;
    await navigator.clipboard.writeText(w.address);
    toast("dashMsg", "Скопійовано ✅");
  };

  // Refresh
  const btnRefresh = safeEl("btnRefresh");
  if(btnRefresh) btnRefresh.onclick = refreshBalanceUI;

  // Receive QR actions
  const btnRegenQR = safeEl("btnRegenQR");
  if(btnRegenQR) btnRegenQR.onclick = ()=>{
    const w = loadWallet();
    if(!w) return;
    renderQR(w.address);
    toast("recvMsg", "QR оновлено ✅");
  };

  const btnShareQR = safeEl("btnShareQR");
  if(btnShareQR) btnShareQR.onclick = async ()=>{
    const w = loadWallet();
    if(!w) return;
    const payload = makeQrPayload(w.address);
    try{
      if(navigator.share){
        await navigator.share({ title:"SETWALLET Address", text: payload });
        toast("recvMsg", "Поділився ✅");
      } else {
        await navigator.clipboard.writeText(payload);
        toast("recvMsg", "Payload скопійовано ✅");
      }
    }catch{
      // ignore
    }
  };

  // Send
  const btnDoSend = safeEl("btnDoSend");
  if(btnDoSend) btnDoSend.onclick = async ()=>{
    const w = loadWallet();
    if(!w) return toast("sendMsg", "Нема гаманця");

    const to = (safeEl("sendTo")?.value || "").trim();
    const amt = Number((safeEl("sendAmt")?.value || "0").trim());
    const memo = (safeEl("sendMemo")?.value || "").trim() || null;

    if(!to) return toast("sendMsg", "Вкажи To address");
    if(!Number.isFinite(amt) || amt <= 0) return toast("sendMsg", "Amount має бути > 0");

    try{
      let privPem;
      if(w.encrypted){
        const pass = prompt("Введи пароль для підпису:");
        if(!pass) throw new Error("Пароль не введено");
        privPem = await decryptText(pass, w.vault);
      }else{
        if(!w.private_pem) throw new Error("Нема private key. Зроби Backup/Import.");
        privPem = w.private_pem;
      }

      // import private key
      const der = pemToDer(privPem);
      const privKey = await crypto.subtle.importKey("pkcs8", der, { name:"ECDSA", namedCurve:"P-256" }, true, ["sign"]);

      await registerWalletIfPossible(w, "sendMsg", { throwOnError: true });

      const nonce = getNextNonce();
      const msg = `${w.address}:${to}:${amt}:${nonce}`;
      const sigB64 = await signMessage(privKey, new TextEncoder().encode(msg));

      const payload = {
        from_address: w.address,
        to_address: to,
        amount: amt,
        nonce,
        memo,
        signature: sigB64,
        public_key: w.public_key_pem
      };

      const res = await apiSendTx(payload);
      toast("sendMsg", `Відправлено ✅ tx_id=${res.tx_id}`);
      if(safeEl("sendMemo")) safeEl("sendMemo").value = "";
      await refreshBalanceUI();
      await refreshHistoryUI();
    }catch(e){
      toast("sendMsg", "Send error: " + e.message);
    }
  };

  // History reload
  const btnReloadHistory = safeEl("btnReloadHistory");
  if(btnReloadHistory) btnReloadHistory.onclick = refreshHistoryUI;
  const btnReloadH2 = safeEl("btnReloadHistory2");
  if(btnReloadH2) btnReloadH2.onclick = refreshHistoryUI;

  // Settings: download backup
  const btnDownloadBackup = safeEl("btnDownloadBackup");
  if(btnDownloadBackup) btnDownloadBackup.onclick = async ()=>{
    const w = loadWallet();
    if(!w) return toast("setMsg", "Нема гаманця");

    const pass = (safeEl("backupPass")?.value || "").trim();

    try{
      // get private pem (decrypt if needed)
      let privPem;
      if(w.encrypted){
        const p = prompt("Введи пароль, щоб розшифрувати private key для backup:");
        if(!p) throw new Error("Пароль не введено");
        privPem = await decryptText(p, w.vault);
      }else{
        if(!w.private_pem) throw new Error("Нема private key");
        privPem = w.private_pem;
      }

      let out = { address: w.address, public_key_pem: w.public_key_pem, encrypted: false };

      if(pass){
        const vault = await encryptText(pass, privPem);
        out.encrypted = true;
        out.vault = vault;
      }else{
        out.private_pem = privPem;
      }

      const blob = new Blob([JSON.stringify(out, null, 2)], { type:"application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `SETWALLET_BACKUP_${w.address}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);

      toast("setMsg", "Backup завантажено ✅");
    }catch(e){
      toast("setMsg", "Backup error: " + e.message);
    }
  };

  // Settings: show public key
  const btnShowPublic = safeEl("btnShowPublic");
  if(btnShowPublic) btnShowPublic.onclick = ()=>{
    const w = loadWallet();
    if(!w) return;
    if(safeEl("walletPub")) safeEl("walletPub").value = w.public_key_pem;
    safeEl("pubModal")?.classList.remove("hidden");
  };

  const btnCloseModal = safeEl("btnCloseModal");
  if(btnCloseModal) btnCloseModal.onclick = ()=> safeEl("pubModal")?.classList.add("hidden");

  // Settings: API base
  const btnSaveApi = safeEl("btnSaveApi");
  if(btnSaveApi) btnSaveApi.onclick = async ()=>{
    const input = safeEl("apiBaseInput");
    if(!input) return;
    const next = normalizeApiBase(input.value.trim());
    if(!next){
      localStorage.removeItem(API_BASE_STORAGE_KEY);
      API_BASE = resolveApiBase();
      updateApiBaseInput();
      toast("setMsg", "API URL скинуто ✅");
      await pingAndUpdateStatus();
      return;
    }

    API_BASE = next;
    localStorage.setItem(API_BASE_STORAGE_KEY, API_BASE);
    toast("setMsg", "API URL збережено ✅");
    await pingAndUpdateStatus();
  };

  // Logout
  const btnLogout = safeEl("btnLogout");
  if(btnLogout) btnLogout.onclick = ()=>{
    clearWallet();
    toast("setMsg", "Локальні дані очищено ✅");
    show("Welcome");
  };
}

// helper for importing PEM (used in send)
function pemToDer(pem){
  const lines = pem.trim().split("\n");
  const b64 = lines.filter(l=>!l.startsWith("-----")).join("");
  return b64ToBuf(b64);
}

// =====================
// Enter views
// =====================
async function onEnterWallet(){
  const w = loadWallet();
  if(!w){
    show("Welcome");
    return;
  }
  if(safeEl("walletAddr")) safeEl("walletAddr").textContent = w.address;
  renderQR(w.address);

  await refreshBalanceUI();
}

async function onEnterReceive(){
  const w = loadWallet();
  if(!w) return;
  renderQR(w.address);
}

async function onEnterHistory(){
  const w = loadWallet();
  if(!w) return;
  await refreshHistoryUI();
}

// Hook view enter on nav
function hookViewEnter(){
  const origShow = show;
  window._show = origShow;

  // override show with hooks
  show = async (view)=>{
    origShow(view);
    if(view === "Wallet") await onEnterWallet();
    if(view === "Receive") await onEnterReceive();
    if(view === "History") await onEnterHistory();
  };
}

// =====================
// Boot
// =====================
(async function boot(){
  bindNav();
  bindActions();
  hookViewEnter();
  updateApiBaseInput();

  await pingAndUpdateStatus();

  const w = loadWallet();
  if(w){
    show("Wallet");
    await onEnterWallet();
  }else{
    show("Welcome");
  }
})();
