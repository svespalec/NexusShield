import sys
import requests
import json
import time
from pathlib import Path

def test_analyze_endpoint(file_path):
    """Test the /analyze endpoint with a PE file and show real-time progress."""
    
    # Check if file exists
    if not Path(file_path).exists():
        print(f"Error: File {file_path} not found")
        return
    
    # Prepare the file for upload
    with open(file_path, 'rb') as f:
        files = {'file': (Path(file_path).name, f, 'application/octet-stream')}
        
        try:
            # Send POST request to the endpoint
            response = requests.post('http://localhost:5000/analyze', files=files)
            
            # Check if request was successful
            response.raise_for_status()
            
            # Get the analysis ID
            result = response.json()
            analysis_id = result['analysis_id']
            
            print(f"Analysis started with ID: {analysis_id}")
            print("Streaming analysis progress...")
            
            # Stream the analysis progress
            with requests.get('http://localhost:5000/stream/' + analysis_id, stream=True) as stream:
                for line in stream.iter_lines():
                    if line:
                        # SSE format starts with "data: "
                        line = line.decode('utf-8')
                        if line.startswith('data: '):
                            data = json.loads(line[6:])  # Skip "data: " prefix
                            status = data.get('status', '')
                            progress = data.get('progress', 0)
                            token_count = data.get('token_count', 0)
                            
                            # Clear line and update progress
                            print(f"\rStatus: {status} | Progress: {progress} | Tokens: {token_count}", end='', flush=True)
                            
                            if status in ['completed', 'error']:
                                print("\nAnalysis complete!")
                                if 'result' in data:
                                    print("\nFinal Analysis:")
                                    print(json.dumps(data['result'], indent=2))
                                break
            
        except requests.exceptions.RequestException as e:
            print(f"Error during request: {e}")
            if hasattr(e.response, 'text'):
                print(f"Server response: {e.response.text}")
        except json.JSONDecodeError:
            print("Error: Could not parse server response as JSON")
            print(f"Raw response: {response.text}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python test.py <path_to_pe_file>")
        sys.exit(1)
        
    test_analyze_endpoint(sys.argv[1])
