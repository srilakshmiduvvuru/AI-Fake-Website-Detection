from flask import Flask, render_template, request
import re
import ipaddress
from urllib.parse import urlparse
import math

app = Flask(__name__)

# Educational heuristic + lightweight ML-style scoring demo.
# This app does NOT visit submitted websites.
SUSPICIOUS_WORDS = {
    "login", "verify", "verification", "account", "secure", "update",
    "password", "wallet", "confirm", "signin", "banking", "support",
    "recover", "gift", "free", "bonus", "urgent"
}
KNOWN_BRANDS = {
    "google": ["google.com"],
    "microsoft": ["microsoft.com", "live.com", "outlook.com"],
    "apple": ["apple.com"],
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "netflix": ["netflix.com"]
}

def get_registered_domain(host):
    host = (host or "").lower().strip(".")
    if not host:
        return ""
    # Basic educational approximation; not a complete Public Suffix List implementation.
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host

def analyze_url(raw_url):
    raw_url = (raw_url or "").strip()
    if not raw_url:
        return {"error": "Please enter a website URL."}

    if not re.match(r"^https?://", raw_url, re.I):
        raw_url = "https://" + raw_url

    try:
        parsed = urlparse(raw_url)
        host = (parsed.hostname or "").lower()
        if not host or "." not in host:
            return {"error": "Enter a valid domain, such as https://example.com"}
        # Validate malformed ports/host parsing.
        _ = parsed.port
    except Exception:
        return {"error": "That URL could not be parsed. Please check it and try again."}

    reasons = []
    score = 0

    if parsed.scheme != "https":
        score += 12
        reasons.append("The URL does not use HTTPS.")
    if "@" in parsed.netloc:
        score += 25
        reasons.append("The URL contains an @ symbol, which can hide the actual destination.")
    if len(raw_url) > 90:
        score += 10
        reasons.append("The URL is unusually long.")
    if host.count("-") >= 2:
        score += 10
        reasons.append("The domain contains several hyphens.")
    if host.count(".") >= 4:
        score += 10
        reasons.append("The hostname has many subdomains.")
    try:
        ipaddress.ip_address(host)
        score += 25
        reasons.append("The URL uses an IP address instead of a normal domain.")
    except ValueError:
        pass

    words_found = sorted(w for w in SUSPICIOUS_WORDS if w in (host + parsed.path + parsed.query).lower())
    if words_found:
        score += min(25, 5 * len(words_found))
        reasons.append("It contains words often seen in deceptive links: " + ", ".join(words_found[:6]) + ".")

    # Flag brand names used on domains not controlled by the brand.
    for brand, official_domains in KNOWN_BRANDS.items():
        if brand in host:
            official = any(host == d or host.endswith("." + d) for d in official_domains)
            if not official:
                score += 30
                reasons.append(f"The hostname mentions '{brand}' but is not on its known official-domain list.")
                break

    # Basic character/entropy-like signal for random-looking hostnames.
    label = host.split(".")[0]
    if len(label) >= 18 and sum(c.isdigit() for c in label) >= 4:
        score += 8
        reasons.append("The hostname looks unusually long or contains many digits.")

    score = min(score, 100)
    if score >= 40:
        verdict = "Potentially Suspicious"
        css_class = "danger"
        summary = "This URL has several warning signs. Avoid entering passwords or payment details until you verify it independently."
    elif score >= 20:
        verdict = "Needs Caution"
        css_class = "warning"
        summary = "Some warning signs were found. Check the exact domain carefully before trusting it."
    else:
        verdict = "No Obvious Warning Signs"
        css_class = "safe"
        summary = "This simple checker found few common warning signs. That does NOT prove the website is genuine or safe."

    if not reasons:
        reasons.append("No warning signs covered by this basic demo were detected.")

    return {
        "url": raw_url,
        "host": host,
        "score": score,
        "verdict": verdict,
        "css_class": css_class,
        "summary": summary,
        "reasons": reasons
    }

@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    if request.method == "POST":
        result = analyze_url(request.form.get("url", ""))
    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
