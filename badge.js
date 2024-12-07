(function() {
    // Extract the current page URL
    const url = window.location.href;

    // Create a container for the badge
    const badge = document.createElement("div");
    badge.style.position = "fixed";
    badge.style.bottom = "10px";
    badge.style.right = "10px";
    badge.style.padding = "8px";
    badge.style.color = "#fff";
    badge.style.fontFamily = "Arial, sans-serif";
    badge.style.borderRadius = "5px";
    badge.style.fontSize = "12px";
    badge.style.textAlign = "center";
    badge.style.boxShadow = "0 0 5px rgba(0,0,0,0.3)";
    badge.style.zIndex = "9999";

    // Send the URL to the FastAPI backend
    fetch("https://api.example.com/validate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url })
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === "safe") {
            badge.style.backgroundColor = "#28a745"; // Green
            badge.innerText = "✔️ Site Verified - Safe";
        } else {
            badge.style.backgroundColor = "#dc3545"; // Red
            badge.innerText = "⚠️ Warning: Phishing Detected!";
        }
    })
    .catch(() => {
        badge.style.backgroundColor = "#ffc107"; // Yellow
        badge.innerText = "⚠️ Unable to Verify";
    });

    // Add the badge to the page
    document.body.appendChild(badge);
})();
