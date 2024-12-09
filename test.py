import sys
import requests
import json
from pathlib import Path

def test_analyze_endpoint(file_path):
    """Test the /analyze endpoint with a PE file."""
    
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
            
            # Parse and pretty print the JSON response
            result = response.json()
            print(json.dumps(result, indent=2))
            
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
