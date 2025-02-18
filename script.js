const Security = {
  iterations: 100000, // PBKDF2 iterations for key derivation
  keySize: 256 / 32, // AES key size (256 bits)
  saltSize: 128 / 8, // Salt size in bytes
  ivSize: 128 / 8, // Initialization vector (IV) size in bytes

  // Generate a key using PBKDF2
  generateKey: (password, salt) => {
    return CryptoJS.PBKDF2(password, salt, {
      keySize: Security.keySize,
      iterations: Security.iterations,
    });
  },

  // Convert ArrayBuffer to CryptoJS WordArray
  arrayBufferToWordArray: (buffer) => {
    const bytes = new Uint8Array(buffer);
    const words = [];
    for (let i = 0; i < bytes.length; i++) {
      words[i >>> 2] |= bytes[i] << (24 - (i % 4) * 8);
    }
    return CryptoJS.lib.WordArray.create(words, bytes.length);
  },

  // Convert CryptoJS WordArray to ArrayBuffer
  wordArrayToArrayBuffer: (wordArray) => {
    const bytes = new Uint8Array(wordArray.sigBytes);
    for (let i = 0; i < wordArray.sigBytes; i++) {
      bytes[i] = (wordArray.words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
    }
    return bytes.buffer;
  },
};

class FileProcessor {
  // Encrypt file with AES
  static async encrypt(file, password) {
    const spinner = document.getElementById("actionButton");
    const salt = CryptoJS.lib.WordArray.random(Security.saltSize);
    const iv = CryptoJS.lib.WordArray.random(Security.ivSize);
    const key = Security.generateKey(password, salt);

    const fileBuffer = await file.arrayBuffer();
    const wordArray = Security.arrayBufferToWordArray(fileBuffer);
    const encrypted = CryptoJS.AES.encrypt(wordArray, key, { iv });

    // Combine salt, IV, and ciphertext
    const combined = CryptoJS.lib.WordArray.create()
      .concat(salt)
      .concat(iv)
      .concat(encrypted.ciphertext);

    spinner.classList.toggle("processing");
    return new Blob([Security.wordArrayToArrayBuffer(combined)], {
      type: "application/octet-stream",
    });
  }

  // Decrypt file with AES
  static async decrypt(file, password) {
    const spinner = document.getElementById("actionButton");
    const buffer = await file.arrayBuffer();
    const encryptedData = Security.arrayBufferToWordArray(buffer);

    // Extract salt, IV, and ciphertext
    const salt = CryptoJS.lib.WordArray.create(
      encryptedData.words.slice(0, Security.saltSize / 4)
    );
    const iv = CryptoJS.lib.WordArray.create(
      encryptedData.words.slice(
        Security.saltSize / 4,
        (Security.saltSize + Security.ivSize) / 4
      )
    );
    const ciphertext = CryptoJS.lib.WordArray.create(
      encryptedData.words.slice((Security.saltSize + Security.ivSize) / 4)
    );

    const key = Security.generateKey(password, salt);
    const decrypted = CryptoJS.AES.decrypt({ ciphertext: ciphertext }, key, {
      iv,
    });

    spinner.classList.toggle("processing");
    return new Blob([Security.wordArrayToArrayBuffer(decrypted)], {
      type: "application/octet-stream",
    });
  }
}

const UI = {
  // Display status messages to the user
  showStatus(message, isError = false) {
    const status = document.getElementById("statusMessage");
    status.textContent = message;
    status.className = `status-message visible ${isError ? "error" : "success"}`;
    setTimeout(() => status.classList.remove("visible"), 5000);
  },

  // Toggle loading state for the action button
  toggleLoading(show) {
    const button = document.getElementById("actionButton");
    button.classList.toggle("processing", show);
  },

  // Update file information in the UI
  updateFileInfo(file) {
    const fileInfo = document.getElementById("fileInfo");
    fileInfo.textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
  },

  // Update password strength indicator
  updatePasswordStrength(password) {
    const strength = Math.min(password.length / 12, 1);
    const bar = document.querySelector(".strength-bar");
    bar.style.width = `${strength * 100}%`;
    bar.style.backgroundColor =
      strength > 0.7
        ? "var(--success-color)" // Green for strong passwords
        : strength > 0.4
        ? "#ffd60a" // Yellow for moderate passwords
        : "var(--error-color)"; // Red for weak passwords
  },
};

// Event listener for file selection
document.getElementById("fileInput").addEventListener("change", (e) => {
  if (e.target.files[0]) UI.updateFileInfo(e.target.files[0]);
});

// Event listener for password input
document.getElementById("keyInput").addEventListener("input", (e) => {
  UI.updatePasswordStrength(e.target.value);
});

// Event listener for encrypt/decrypt button
document.getElementById("actionButton").addEventListener("click", async () => {
  const fileInput = document.getElementById("fileInput");
  const keyInput = document.getElementById("keyInput");
  const action = document.getElementById("action").value;

  if (!fileInput.files[0] || !keyInput.value) {
    UI.showStatus("Please select a file and enter passphrase!", true);
    return;
  }

  if (action === "encrypt" && keyInput.value.length < 8) {
    UI.showStatus("Passphrase must be at least 8 characters!", true);
    return;
  }

  try {
    UI.toggleLoading(true);
    const file = fileInput.files[0];
    const password = keyInput.value;

    const processedBlob =
      action === "encrypt"
        ? await FileProcessor.encrypt(file, password)
        : await FileProcessor.decrypt(file, password);

    // Determine file extension for download
    const ext =
      action === "encrypt"
        ? ".encrypted"
        : file.name.replace(/\.encrypted$/, "");

    const link = document.createElement("a");
    link.href = URL.createObjectURL(processedBlob);
    link.download = `${ext}`;
    link.click();

    UI.showStatus(`File ${action}ed successfully! Downloading...`);
  } catch (error) {
    UI.showStatus("Error: Invalid passphrase or file", true);
  } finally {
    UI.toggleLoading(false);
  }
});

// Theme toggle button functionality
document.getElementById("themeToggle").addEventListener("click", () => {
  document.body.classList.toggle("dark-mode");
  const isDark = document.body.classList.contains("dark-mode");
  const toggle = document.getElementById("themeToggle");
  toggle.textContent = isDark ? "☀️" : "🌙";
  toggle.classList.add("rotate");
  setTimeout(() => toggle.classList.remove("rotate"), 600);
});
