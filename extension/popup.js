const input = document.getElementById("backendUrl");
const status = document.getElementById("status");

chrome.storage.sync.get("backend_url", (data) => {
  input.value = data.backend_url || "http://localhost:8000";
});

document.getElementById("saveBtn").addEventListener("click", () => {
  const url = input.value.trim().replace(/\/$/, "");
  chrome.storage.sync.set({ backend_url: url }, () => {
    status.style.display = "block";
    setTimeout(() => (status.style.display = "none"), 1500);
  });
});
