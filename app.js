const wallet = {
  address: "0xA1TSETING000000000",
  alt: 1200,
  altst: 300
};

document.getElementById("address").innerText = wallet.address;
document.getElementById("alt").innerText = wallet.alt;
document.getElementById("altst").innerText = wallet.altst;

const history = [
  "+50 ALT",
  "-10 ALT",
  "+100 ALTST"
];

const list = document.getElementById("history");
history.forEach(tx => {
  const li = document.createElement("li");
  li.textContent = tx;
  list.appendChild(li);
});

function copyAddress() {
  navigator.clipboard.writeText(wallet.address);
}
