import os
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
import google.generativeai as genai
from dotenv import load_dotenv
from peparse import PEAnalyzer
import json

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

def analyze_with_gemini(indicators):
    """Send the indicators to Gemini for analysis."""
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
    "iocs": [<list of identified IOCs>],
    "suspicious_behaviors": [<list of suspicious behaviors found>],
    "explanation": "<detailed explanation of the analysis>"
}}"""

    try:
        response = model.generate_content(prompt)
        # Clean up the response text
        text = response.text
        
        # Remove markdown code block if present
        if "```json" in text:
            text = text.split("```json")[1]
        if "```" in text:
            text = text.split("```")[0]
            
        # Strip any leading/trailing whitespace
        text = text.strip()
        
        # Parse the JSON
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {
                "malware_probability": 0,
                "iocs": [],
                "suspicious_behaviors": [],
                "explanation": f"Error parsing Gemini response: {text}"
            }
    except Exception as e:
        return {
            "error": f"Gemini API error: {str(e)}",
            "malware_probability": 0,
            "iocs": [],
            "suspicious_behaviors": [],
            "explanation": "Failed to analyze with Gemini API"
        }

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    try:
        # Save the uploaded file
        file.save(filepath)
        
        # Analyze PE file
        analyzer = PEAnalyzer()
        pe_analysis = analyzer.analyze_pe_file(filepath)
        
        if 'error' in pe_analysis:
            return jsonify({'error': pe_analysis['error']}), 400
        
        # Extract key indicators
        key_indicators = extract_key_indicators(pe_analysis)
        
        # Get Gemini analysis
        gemini_analysis = analyze_with_gemini(key_indicators)
        
        # Combine manual and Gemini analysis
        result = {
            'manual_analysis': key_indicators,
            'gemini_analysis': gemini_analysis
        }
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
        
    finally:
        # Clean up temporary file with retry mechanism
        for _ in range(3):  # Try up to 3 times
            try:
                if os.path.exists(filepath):
                    os.close(os.open(filepath, os.O_RDONLY))  # Force close any open handles
                    os.remove(filepath)
                break
            except Exception:
                import time
                time.sleep(0.1)  # Wait a bit before retrying

if __name__ == '__main__':
    app.run(debug=True)
