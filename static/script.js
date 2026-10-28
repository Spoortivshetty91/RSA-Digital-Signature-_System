
const generateBtn = document.getElementById("generateBtn");
const publicKeyInput = document.getElementById("publicKey");
const keyStatus = document.getElementById("keyStatus");

const messageInput = document.getElementById("message");
const signBtn = document.getElementById("signBtn");
const messageHash = document.getElementById("messageHash");
const signatureInput = document.getElementById("signature");
const signStatus = document.getElementById("signStatus");

const verifyBtn = document.getElementById("verifyBtn");
const verifyResult = document.getElementById("verifyResult");

const senderPackage = document.getElementById("senderPackage");
const receiverPackage = document.getElementById("receiverPackage");
const receivedMessage = document.getElementById("receivedMessage");
const exportStatus = document.getElementById("exportStatus");
const receiverResult = document.getElementById("receiverResult");

let lastSignedPackage = null;

// Common API request function
async function apiRequest(url, data = {}) {
    const response = await fetch(url, {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(data)
    });

    const result = await response.json();

    if (!response.ok) {
        throw new Error(
            result.detail || "Request failed. Please try again."
        );
    }

    return result;
}

// 1. Generate RSA keys
generateBtn.addEventListener("click", async () => {
    try {
        keyStatus.textContent = "Generating RSA keys...";

        const result = await apiRequest("/api/generate-keys");

        // Display the public key in the frontend
        publicKeyInput.value = result.public_key;

        keyStatus.textContent = result.message;
    } catch (error) {
        keyStatus.textContent = "Error: " + error.message;
        console.error(error);
    }
});

// 2. Sign a message
signBtn.addEventListener("click", async () => {
    try {
        if (!messageInput.value.trim()) {
            throw new Error("Please enter a message to sign.");
        }

        signStatus.textContent = "Signing message...";

        const result = await apiRequest("/api/sign", {
            message: messageInput.value
        });
messageHash.value = result.message_hash;
        signatureInput.value = result.signature;

        signStatus.textContent = result.message || "Message signed successfully.";
    } catch (error) {
        signStatus.textContent = "Error: " + error.message;
        console.error(error);
    }
});

// 3. Verify a signature
verifyBtn.addEventListener("click", async () => {
    try {
        const result = await apiRequest("/api/verify", {
            message: messageInput.value,
            signature: signatureInput.value,
            public_key: publicKeyInput.value
        });

        verifyResult.textContent = result.message;
        verifyResult.className = result.valid
            ? "result success"
            : "result failure";
    } catch (error) {
        verifyResult.textContent = "Error: " + error.message;
        verifyResult.className = "result failure";
    }
});

// 4. Prepare a sender package
document.getElementById("exportBtn").addEventListener("click", () => {
    const message = messageInput.value;
    const signature = signatureInput.value;
    const publicKey = publicKeyInput.value;

    if (!message || !signature || !publicKey) {
        exportStatus.textContent =
            "Generate keys and sign a message before exporting.";
        return;
    }

    lastSignedPackage = {
        message: message,
        signature: signature,
        public_key: publicKey,
        algorithm: "RSA-PSS with SHA-256"
    };

    senderPackage.value = JSON.stringify(lastSignedPackage, null, 2);
    exportStatus.textContent = "Message package prepared successfully.";
});

// 5. Copy the sender package
document.getElementById("copyPackageBtn").addEventListener("click", async () => {
    if (!senderPackage.value) {
        exportStatus.textContent = "Prepare the message package first.";
        return;
    }

    try {
        await navigator.clipboard.writeText(senderPackage.value);
        exportStatus.textContent = "Package copied successfully.";
    } catch (error) {
        exportStatus.textContent =
            "Copy unavailable. Select and copy the package manually.";
    }
});

// 6. Import and verify the receiver package
document.getElementById("receiveVerifyBtn").addEventListener("click", async () => {
    try {
        const received = JSON.parse(receiverPackage.value);

        if (
            typeof received.message !== "string" ||
            typeof received.signature !== "string" ||
            typeof received.public_key !== "string" ||
            !received.signature ||
            !received.public_key
        ) {
            throw new Error(
                "Package must contain a message, signature, and public key."
            );
        }

        receivedMessage.value = received.message;

        const result = await apiRequest("/api/verify", {
            message: received.message,
            signature: received.signature,
            public_key: received.public_key
        });

        receiverResult.textContent = result.message;
        receiverResult.className = result.valid
            ? "result success"
            : "result failure";
    } catch (error) {
        receiverResult.textContent =
            error instanceof SyntaxError
                ? "Invalid JSON. Paste the complete message package."
                : error.message;

        receiverResult.className = "result failure";
    }
});
