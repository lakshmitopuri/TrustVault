const API = "https://trustvault-2-mwgv.onrender.com";

const loginForm = document.getElementById("loginForm");
const registerForm = document.getElementById("registerForm");
const loginSection = document.querySelector(".login-card");
const dashboard = document.getElementById("dashboard");
const message = document.getElementById("message");
const dashboardMessage = document.getElementById("dashboardMessage");
const documentList = document.getElementById("documentList");

let token = sessionStorage.getItem("trustvault_token");

// Send requests to the backend
async function apiRequest(path, options = {}) {
  const response = await fetch(API + path, {
    ...options,
    headers: {
      ...(options.headers || {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {})
    }
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.error || data.message || "Request failed");
  }

  return data;
}

// Show the dashboard after login
function showDashboard() {
  if (loginSection) loginSection.hidden = true;
  if (dashboard) dashboard.hidden = false;
  loadDocuments();
}

// Register a new account
if (registerForm) {
  registerForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    message.textContent = "Creating account...";

    try {
      const data = await apiRequest("/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: document.getElementById("registerEmail").value.trim(),
          password: document.getElementById("registerPassword").value
        })
      });

      message.textContent =
        data.message || "Account created! You can now sign in.";

      registerForm.reset();
    } catch (error) {
      message.textContent = error.message;
    }
  });
}

// Log in
if (loginForm) {
  loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    message.textContent = "Signing in...";

    try {
      const data = await apiRequest("/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: document.getElementById("email").value.trim(),
          password: document.getElementById("password").value
        })
      });

      token = data.access_token;

      if (!token) {
        throw new Error("Login response did not include an access token.");
      }

      sessionStorage.setItem("trustvault_token", token);
      message.textContent = "Login successful!";

      showDashboard();
    } catch (error) {
      message.textContent = error.message;
    }
  });
}

// Load documents
async function loadDocuments() {
  if (!dashboardMessage || !documentList) return;

  dashboardMessage.textContent = "Loading documents...";
  documentList.replaceChildren();

  try {
    const data = await apiRequest("/documents/");
    const documents = Array.isArray(data)
      ? data
      : data.documents || data.items || [];

    if (documents.length === 0) {
      dashboardMessage.textContent = "No documents found yet.";
      return;
    }

    for (const doc of documents) {
      const item = document.createElement("li");
      const name = document.createElement("span");
      const downloadButton = document.createElement("button");

      name.textContent = doc.filename || doc.name || "Document";
      downloadButton.textContent = "Download";

      downloadButton.addEventListener("click", async () => {
        try {
          const response = await fetch(
            `${API}/documents/${doc.id}/download`,
            {
              headers: { Authorization: `Bearer ${token}` }
            }
          );

          if (!response.ok) {
            throw new Error("Download failed");
          }

          const blob = await response.blob();
          const url = URL.createObjectURL(blob);
          const link = document.createElement("a");

          link.href = url;
          link.download = doc.filename || "document";
          document.body.appendChild(link);
          link.click();
          link.remove();

          setTimeout(() => URL.revokeObjectURL(url), 1000);
        } catch (error) {
          dashboardMessage.textContent = error.message;
        }
      });

      item.append(name, " ", downloadButton);
      documentList.appendChild(item);
    }

    dashboardMessage.textContent = "Documents loaded.";
  } catch (error) {
    dashboardMessage.textContent = error.message;
  }
}

// Reload documents button
const loadButton = document.getElementById("loadButton");

if (loadButton) {
  loadButton.addEventListener("click", loadDocuments);
}

// Upload a document
const uploadButton = document.getElementById("uploadButton");

if (uploadButton) {
  uploadButton.addEventListener("click", async () => {
    const fileInput = document.getElementById("documentFile");
    const file = fileInput?.files?.[0];

    if (!file) {
      dashboardMessage.textContent = "Please select a document first.";
      return;
    }

    const formData = new FormData();
    formData.append("file", file);

    dashboardMessage.textContent = "Uploading...";

    try {
      await apiRequest("/documents/upload", {
        method: "POST",
        body: formData
      });

      dashboardMessage.textContent = "Upload successful!";
      fileInput.value = "";
      await loadDocuments();
    } catch (error) {
      dashboardMessage.textContent = error.message;
    }
  });
}

// Restore the dashboard if the session has a token
if (token) {
  showDashboard();
}
