
const generateBtn = document.getElementById("generateBtn");
const signBtn = document.getElementById("signBtn");
const verifyBtn = document.getElementById("verifyBtn");

const messageInput = document.getElementById("message");
const publicKeyInput = document.getElementById("publicKey");
const messageHashInput = document.getElementById("messageHash");
const signatureInput = document.getElementById("signature");

const keyStatus = document.getElementById("keyStatus");
const signStatus = document.getElementById("signStatus");
const verifyResult = document.getElementById("verifyResult");

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
        throw new Error(result.detail || "Request failed.");
    }

    return result;
}

// Generate RSA key pair
generateBtn.addEventListener("click", async () => {
    try {
        const result = await apiRequest("/api/generate-keys");

        publicKeyInput.value = result.public_key;
        messageHashInput.value = "";
        signatureInput.value = "";

        keyStatus.textContent = result.message;
        signStatus.textContent = "";
        verifyResult.textContent = "Sign a message to begin verification.";
        verifyResult.className = "result";
    } catch (error) {
        keyStatus.textContent = error.message;
    }
});

// Sign the message using the private key
signBtn.addEventListener("click", async () => {
    try {
        const result = await apiRequest("/api/sign", {
            message: messageInput.value
        });

        messageHashInput.value = result.message_hash;
        signatureInput.value = result.signature;
        signStatus.textContent = result.message;

        verifyResult.textContent = "Now verify the signature.";
        verifyResult.className = "result";
    } catch (error) {
        signStatus.textContent = error.message;
    }
});

// Verify using the supplied public key
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
        verifyResult.textContent = error.message;
        verifyResult.className = "result failure";
    }
});
