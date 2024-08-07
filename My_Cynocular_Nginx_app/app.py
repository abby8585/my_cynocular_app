from flask import Flask, request, jsonify
import requests
import os
import exiftool
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpeg', 'jpg', 'pdf', 'csv'}

# GPT-4 API settings
GPT_API_URL = 'https://api.openai.com/v1/engines/gpt-4/completions'
GPT_API_KEY = os.getenv('GPT_API_KEY')

# VirusTotal API settings
VT_API_URL = 'https://www.virustotal.com/api/v3'
VT_API_KEY = os.getenv('VT_API_KEY')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def summarize_with_gpt(prompt):
    headers = {
        'Authorization': f'Bearer {GPT_API_KEY}',
        'Content-Type': 'application/json'
    }
    payload = {
        'prompt': prompt,
        'max_tokens': 400,
        'temperature': 0.3
    }

    try:
        response = requests.post(GPT_API_URL, json=payload, headers=headers)
        response.raise_for_status()  # Check if the request was successful
        result = response.json().get('choices', [{}])[0].get('text', 'No result')
        return result
    except requests.exceptions.RequestException as e:
        return f"Error summarizing with GPT: {e}"

def extract_metadata(file_path):
    try:
        with exiftool.ExifTool() as et:
            metadata = et.get_metadata(file_path)
        return metadata
    except Exception as e:
        return f"Error extracting metadata: {e}"

@app.route('/vt/scan', methods=['POST'])
def vt_scan():
    data = request.json
    file_hash = data.get('fileHash', '')
    url = data.get('url', '')
    ip = data.get('ip', '')

    headers = {
        'x-apikey': VT_API_KEY
    }

    if file_hash:
        endpoint = f'{VT_API_URL}/files/{file_hash}'
    elif url:
        endpoint = f'{VT_API_URL}/urls/{url}'
    elif ip:
        endpoint = f'{VT_API_URL}/ips/{ip}'
    else:
        return jsonify({'error': 'No valid parameter provided'}), 400

    try:
        response = requests.get(endpoint, headers=headers)
        response.raise_for_status()  # Check if the request was successful
        result = response.json()
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f"Error fetching VirusTotal scan result: {e}"}), 500

    summary = summarize_with_gpt(str(result))
    return jsonify({'result': result, 'summary': summary})

@app.route('/vt/dns', methods=['POST'])
def vt_dns():
    data = request.json
    domain = data.get('domain', '')

    headers = {
        'x-apikey': VT_API_KEY
    }

    try:
        response = requests.get(f'{VT_API_URL}/domains/{domain}', headers=headers)
        response.raise_for_status()  # Check if the request was successful
        result = response.json()
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f"Error fetching VirusTotal DNS result: {e}"}), 500

    summary = summarize_with_gpt(str(result))
    return jsonify({'result': result, 'summary': summary})

@app.route('/gpt', methods=['POST'])
def gpt_request():
    data = request.json
    prompt = data.get('text', '')

    try:
        summary = summarize_with_gpt(prompt)
        return jsonify({'result': summary})
    except Exception as e:
        return jsonify({'error': f"Error fetching GPT result: {e}"}), 500

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join('/path/to/save', filename)
        try:
            file.save(file_path)  # Save file to the desired location
            # Extract metadata using pyexiftool
            metadata = extract_metadata(file_path)
            if isinstance(metadata, str) and metadata.startswith("Error"):
                return jsonify({'error': metadata}), 500

            # Create a prompt for the GPT summary
            prompt = f"Metadata:\n{metadata}\n\nProvide a cybersecurity-related analysis and summary."
            # Summarize metadata with GPT
            metadata_summary = summarize_with_gpt(prompt)
            return jsonify({'success': 'File uploaded successfully', 'metadata': metadata, 'metadata_summary': metadata_summary}), 200
        except Exception as e:
            return jsonify({'error': f"Error processing file: {e}"}), 500
    else:
        return jsonify({'error': 'Invalid file type'}), 400

@app.route('/complete_summary', methods=['POST'])
def complete_summary():
    data = request.json
    file_metadata_summary = data.get('file_metadata_summary', '')
    vt_scan_result = data.get('vt_scan_result', '')
    vt_dns_result = data.get('vt_dns_result', '')

    prompt_parts = []
    if file_metadata_summary:
        prompt_parts.append(f"File Details:\n{file_metadata_summary}")
    if vt_scan_result:
        prompt_parts.append(f"Security Scan Result:\n{vt_scan_result}")
    if vt_dns_result:
        prompt_parts.append(f"DNS Result:\n{vt_dns_result}")

    if not prompt_parts:
        return jsonify({'error': 'No data provided for summary'}), 400

    prompt = "\n\n".join(prompt_parts) + "\n\nProvide a combined cybersecurity-related analysis and summary."

    try:
        final_summary = summarize_with_gpt(prompt)
        return jsonify({'summary': final_summary})
    except Exception as e:
        return jsonify({'error': f"Error summarizing final summary: {e}"}), 500

if __name__ == '__main__':
    app.run(debug=True)
