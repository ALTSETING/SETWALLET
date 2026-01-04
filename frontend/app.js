const API_BASE = "https://setwallet.onrender.com";

const btn = document.getElementById("checkBtn");
const statusEl = document.getElementById("status");

btn.onclick = async () => {
  statusEl.textContent = "checking...";
  try {
    const res = await fetch(API_BASE + "/health");
    if (!res.ok) throw new Error("bad response");
    const data = await res.json();
    statusEl.textContent = "ONLINE ✅";
  } catch (e) {
    statusEl.textContent = "OFFLINE ❌";
  }
};
