const state = {
  mode: "not connected",
  room: "-",
  ownUser: ""
};

const $ = (id) => document.getElementById(id);

const api = async (url, body) => {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body ?? {})
  });
  if (!response.ok) throw new Error(await response.text());
  return response.json();
};

const refreshRoom = () => {
  $("roomMode").textContent = state.mode;
  $("roomName").textContent = state.room;
};

const updateFileAccept = () => {
  const kind = $("uploadKind").value;
  // Keep the picker aligned with the native attachment validator.
  $("fileInput").accept = kind === "image"
    ? ".png,.jpg,.jpeg,.bmp,image/png,image/jpeg,image/bmp"
    : kind === "voice"
      ? ".wav,audio/wav,audio/x-wav"
      : ".txt,.md,.markdown,.log,.csv,.json,.xml,.yml,.yaml,.ini,.conf,.cfg,text/plain,text/markdown,text/csv,application/json,application/xml,text/xml";
  $("fileInput").value = "";
};

const shouldShowStatus = (message) => {
  const text = message.toLowerCase();
  // Keep low-level endpoint noise hidden, but show security-critical state so
  // PKI and group-key failures are visible in the browser UI.
  return text.includes("pki") || text.includes("mtls") || text.includes("identity") || text.includes("group key");
};

const addMessage = (kind, message) => {
  if (kind === "log") return;
  if (kind === "status" && !shouldShowStatus(message)) return;

  let sender = "";
  let body = message;
  let type = kind;

  if (kind === "message") {
    try {
      const parsed = JSON.parse(message);
      sender = parsed.payload?.displayName || parsed.from || "";
      type = parsed.type || kind;
      // Metadata frames are used to prepare attachment rendering; the file callback draws the item.
      if (type.endsWith("_meta")) return;
      if (parsed.payload?.private === true) type = `${type} private`;
      body = parsed.content || parsed.name || message;
    } catch {
      body = message;
    }
  }

  const row = document.createElement("article");
  row.className = "message";
  if (sender && sender.toLowerCase() === state.ownUser.toLowerCase()) row.classList.add("own");
  if (kind === "error") row.classList.add("error");

  const meta = document.createElement("div");
  meta.className = "meta";
  meta.textContent = sender ? `[${sender}][${type}]` : `[${type}]`;

  const content = document.createElement("div");
  content.className = "body";
  content.textContent = body;

  row.append(meta, content);
  $("messages").append(row);
  $("messages").scrollTop = $("messages").scrollHeight;
};

const addAttachment = (item) => {
  if (!item.Url) return;

  const row = document.createElement("article");
  row.className = "message";
  if (item.Sender && item.Sender.toLowerCase() === state.ownUser.toLowerCase()) row.classList.add("own");

  const meta = document.createElement("div");
  meta.className = "meta";
  meta.textContent = item.Sender ? `[${item.Sender}][${item.Kind}]` : `[${item.Kind}]`;

  let content;
  if (item.Kind === "image") {
    content = document.createElement("img");
    content.className = "mediaImage";
    content.src = item.Url;
    content.alt = item.Name || "image";
  } else if (item.Kind === "voice") {
    content = document.createElement("audio");
    content.className = "mediaAudio";
    content.src = item.Url;
    content.controls = true;
    content.preload = "metadata";
  } else {
    content = document.createElement("a");
    content.href = item.Url;
    content.download = item.Name || "";
    content.textContent = item.Name || "file";
  }

  row.append(meta, content);
  $("messages").append(row);
  $("messages").scrollTop = $("messages").scrollHeight;
};

const source = new EventSource("/events");
source.onmessage = (event) => {
  const item = JSON.parse(event.data);
  if (item.Kind === "image" || item.Kind === "voice" || item.Kind === "file") {
    addAttachment(item);
    return;
  }
  addMessage(item.Kind, item.Message);
};

document.querySelectorAll(".tab").forEach((tab) => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach((item) => item.classList.remove("active"));
    document.querySelectorAll(".panel").forEach((item) => item.classList.remove("active"));
    tab.classList.add("active");
    $(`${tab.dataset.tab}Panel`).classList.add("active");
  });
});

$("hostButton").addEventListener("click", async () => {
  state.mode = "host";
  state.room = $("hostRoom").value.trim();
  state.ownUser = $("hostUser").value.trim();
  refreshRoom();
  // Host is a participant. The separate Server process owns listening and TLS.
  await api("/api/host", {
    serverUrl: $("hostServerUrl").value.trim(),
    roomId: state.room,
    username: state.ownUser,
    password: $("hostPassword").value
  });
});

$("joinButton").addEventListener("click", async () => {
  state.mode = "client";
  state.room = $("joinRoom").value.trim();
  state.ownUser = $("joinUser").value.trim();
  refreshRoom();
  await api("/api/join", {
    url: $("joinUrl").value.trim(),
    roomId: state.room,
    username: state.ownUser,
    password: $("joinPassword").value
  });
});

$("stopButton").addEventListener("click", async () => {
  await api("/api/stop");
  state.mode = "not connected";
  state.room = "-";
  refreshRoom();
});

$("sendForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const target = $("targetInput").value.trim();

  // The same optional target applies to the selected attachment and the text line.
  const file = $("fileInput").files[0];
  if (file) {
    const form = new FormData();
    form.append("file", file);
    form.append("target", target);
    const response = await fetch(`/api/upload?kind=${encodeURIComponent($("uploadKind").value)}`, {
      method: "POST",
      body: form
    });
    if (!response.ok) throw new Error(await response.text());
    $("fileInput").value = "";
  }

  const text = $("messageInput").value.trim();
  if (text) {
    await api("/api/send", { text, target });
    $("messageInput").value = "";
  }
});

$("uploadKind").addEventListener("change", updateFileAccept);

refreshRoom();
updateFileAccept();
