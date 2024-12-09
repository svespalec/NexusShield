import os
from flask import Flask, request, jsonify, Response, stream_with_context
from werkzeug.utils import secure_filename
import google.generativeai as genai
from dotenv import load_dotenv
from peparse import PEAnalyzer
import json
import time
import uuid
from threading import Lock

# Load environment variables
load_dotenv()

# Configure Gemini
genai.configure(api_key=os.getenv('GOOGLE_API_KEY'))
model = genai.GenerativeModel('gemini-1.5-pro')

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = 'temp_uploads'

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Store analysis status
analysis_status = {}
status_lock = Lock()

def extract_key_indicators(analysis):
    """Extract the most important indicators for malware detection."""
    return {
        "file_info": {
            "type": analysis["file_info"]["type"],
            "hashes": analysis["file_info"]["hashes"]
        },
        "suspicious_imports": analysis["suspicious_imports"],
        "high_entropy_sections": analysis["high_entropy_sections"],
        "anomalies": analysis["anomalies"],
        "section_info": {
            "number_of_sections": analysis["section_info"]["number_of_sections"],
            "suspicious_sections": [
                section for section in analysis["section_info"]["sections"]
                if section["entropy"] > 7.0 or 
                (section["is_executable"] and section["is_writable"])
            ]
        }
    }

def count_tokens_gemini(text):
    """Calculate token count for Gemini 1.5 Pro based on an approximation."""
    # Assuming 1 token = 4 characters on average
    return len(text) // 4

def analyze_with_gemini(indicators, analysis_id):
    print("indicators sending: ", indicators)
    """Send the indicators to Gemini for analysis with streaming support."""
    prompt = f"""Analyze this PE file for potential malware characteristics. Here are the key indicators:

1. File Information:
   - Type: {indicators['file_info']['type']}
   - Hashes: {indicators['file_info']['hashes']}

2. Suspicious Imports: {indicators['suspicious_imports']}

3. High Entropy Sections: {indicators['high_entropy_sections']}

4. Anomalies: {indicators['anomalies']}

5. Section Information:
   - Number of sections: {indicators['section_info']['number_of_sections']}
   - Suspicious sections: {indicators['section_info']['suspicious_sections']}

Based on these indicators, analyze if this is likely malware. Return your analysis in this exact JSON format:
{{
    "malware_probability": <number between 0-100>,
    "iocs": [<list of network IOCs, C2 servers, registry keys, file paths, or other malicious artifacts found - DO NOT include file hashes>],
    "suspicious_behaviors": [<list of specific suspicious behaviors, each as a concise point>],
    "analysis_points": [<list of specific reasons why this file is suspicious, one detailed point per array element>],
    "explanation": "<brief overall conclusion about the file's maliciousness>"
}}

Note: For the analysis_points, break down each suspicious characteristic into a separate, detailed explanation."""

    # Update token count
    token_count = count_tokens_gemini(prompt)
    with status_lock:
        analysis_status[analysis_id]["token_count"] = token_count
        analysis_status[analysis_id]["status"] = "analyzing"

    try:
        response = model.generate_content(prompt, stream=True)
        accumulated_response = ""
        
        for chunk in response:
            if chunk.text:
                accumulated_response += chunk.text
                with status_lock:
                    analysis_status[analysis_id]["partial_response"] = accumulated_response
                    analysis_status[analysis_id]["progress"] += 1

        # Clean up the response text
        text = accumulated_response
        
        # Remove markdown code block if present
        if "```json" in text:
            text = text.split("```json")[1]
        if "```" in text:
            text = text.split("```")[0]
            
        # Strip any leading/trailing whitespace
        text = text.strip()
        
        # Parse the JSON
        try:
            result = json.loads(text)
            with status_lock:
                analysis_status[analysis_id]["status"] = "completed"
                analysis_status[analysis_id]["result"] = result
            return result
        except json.JSONDecodeError:
            error_result = {
                "malware_probability": 0,
                "iocs": [],
                "suspicious_behaviors": [],
                "analysis_points": [],
                "explanation": f"Error parsing Gemini response: {text}"
            }
            with status_lock:
                analysis_status[analysis_id]["status"] = "error"
                analysis_status[analysis_id]["result"] = error_result
            return error_result
    except Exception as e:
        error_result = {
            "error": f"Gemini API error: {str(e)}",
            "malware_probability": 0,
            "iocs": [],
            "suspicious_behaviors": [],
            "analysis_points": [],
            "explanation": "Failed to analyze with Gemini API"
        }
        with status_lock:
            analysis_status[analysis_id]["status"] = "error"
            analysis_status[analysis_id]["result"] = error_result
        return error_result

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    # Generate unique analysis ID
    analysis_id = str(uuid.uuid4())
    
    # Initialize analysis status
    with status_lock:
        analysis_status[analysis_id] = {
            "status": "starting",
            "progress": 0,
            "token_count": 0,
            "partial_response": "",
            "result": None
        }
    
    try:
        # Save the uploaded file
        file.save(filepath)
        
        # Analyze PE file
        analyzer = PEAnalyzer()
        pe_analysis = analyzer.analyze_pe_file(filepath)
        
        if 'error' in pe_analysis:
            return jsonify({'error': pe_analysis['error'], 'analysis_id': analysis_id}), 400
        
        # Extract key indicators
        key_indicators = extract_key_indicators(pe_analysis)
        
        # Start Gemini analysis in a way that allows streaming
        gemini_analysis = analyze_with_gemini(key_indicators, analysis_id)
        
        # Combine manual and Gemini analysis
        result = {
            'analysis_id': analysis_id,
            'manual_analysis': key_indicators,
            'gemini_analysis': gemini_analysis
        }
        
        return jsonify(result)
        
    except Exception as e:
        with status_lock:
            analysis_status[analysis_id]["status"] = "error"
            analysis_status[analysis_id]["result"] = {"error": str(e)}
        return jsonify({'error': str(e), 'analysis_id': analysis_id}), 500
        
    finally:
        # Clean up temporary file with retry mechanism
        for _ in range(3):
            try:
                if os.path.exists(filepath):
                    os.close(os.open(filepath, os.O_RDONLY))
                    os.remove(filepath)
                break
            except Exception:
                time.sleep(0.1)

@app.route('/status/<analysis_id>', methods=['GET'])
def get_status(analysis_id):
    """Get the current status of an analysis."""
    with status_lock:
        if analysis_id not in analysis_status:
            return jsonify({"error": "Analysis ID not found"}), 404
        
        status_data = analysis_status[analysis_id].copy()
        
        # Clean up completed analyses after a while
        if status_data["status"] in ["completed", "error"]:
            if time.time() - status_data.get("completion_time", 0) > 3600:  # Clean up after 1 hour
                del analysis_status[analysis_id]
        
        return jsonify(status_data)

@app.route('/stream/<analysis_id>')
def stream_analysis(analysis_id):
    """Stream the analysis results as they come in."""
    def generate():
        while True:
            with status_lock:
                if analysis_id not in analysis_status:
                    yield f"data: {json.dumps({'error': 'Analysis not found'})}\n\n"
                    break
                
                status = analysis_status[analysis_id]
                yield f"data: {json.dumps(status)}\n\n"
                
                if status['status'] in ['completed', 'error']:
                    break
            
            time.sleep(0.5)  # Check every 500ms
    
    return Response(stream_with_context(generate()), mimetype='text/event-stream')

if __name__ == '__main__':
    app.run(debug=True)
