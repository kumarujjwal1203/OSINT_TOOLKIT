from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv
import os, hashlib, requests, re
from PIL import Image
from PIL.ExifTags import TAGS

load_dotenv()

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 8 * 1024 * 1024  # 8 MB max upload

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/health')
def health():
    return "OK", 200

# ---------------------------
# Password Breach Scanner
# ---------------------------
@app.route('/scan-password', methods=['POST'])
def scan_password():
    password = request.form.get('password', '')
    if not password:
        return jsonify({"error": "Password required"}), 400

    sha1pwd = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1pwd[:5]
    suffix = sha1pwd[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    res = requests.get(url)
    if res.status_code != 200:
        return jsonify({"error": "API request failed"}), 500

    hashes = (line.split(':') for line in res.text.splitlines())
    count = 0
    for h, c in hashes:
        if h == suffix:
            count = int(c)
            break

    return jsonify({"breached": count > 0, "count": count})

# ---------------------------
# Simple Email Lookup
# ---------------------------
@app.route('/lookup-email', methods=['POST'])
def lookup_email():
    email = request.form.get('email', '')
    if not email:
        return jsonify({"error": "Email required"}), 400

    pattern = r"^[\w\.-]+@([\w\.-]+)$"
    match = re.match(pattern, email)
    if not match:
        return jsonify({"error": "Invalid email format"}), 400

    domain = match.group(1).lower()
    trusted_domains = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "protonmail.com"]

    if domain in trusted_domains:
        status = f"✅ Common provider detected: {domain}"
    else:
        status = f"ℹ️ Custom / less common domain: {domain}"

    return jsonify({"breached": False, "domain": domain, "status": status})

# ---------------------------
# Image Metadata Extractor
# ---------------------------
@app.route('/extract-image', methods=['POST'])
def extract_image():
    if 'image' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['image']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400

    try:
        img = Image.open(file)
        exifdata = img._getexif()
        if not exifdata:
            return jsonify({"metadata": {}, "message": "No EXIF metadata found."})

        metadata = {}
        for tag_id, value in exifdata.items():
            tag = TAGS.get(tag_id, tag_id)
            metadata[str(tag)] = str(value)

        return jsonify({"metadata": metadata})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(debug=True)
