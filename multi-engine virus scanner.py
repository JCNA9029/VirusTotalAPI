import hashlib
import requests

def sha256_file(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        #Read the file in chunks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Example usage
file_path = r"c:\Users\koala\Desktop\Terraria.url"
sha = sha256_file(file_path)
url = "https://www.virustotal.com/api/v3/files"
url2 = "https://www.virustotal.com/api/v3/files/" + sha

files = {"file": (file_path, open(file_path, "rb"), "application/octet-stream")}
headers = {
    "accept": "application/json",
    "x-apikey": "acf09e97046fd748b4cdc5a9cd2a53d6da2ca56d57eb8602f9e0374146ad78a3"
}
responserequest = requests.post(url, files=files, headers=headers)

print("SHA256 of the file:" + sha256_file(file_path))
response = requests.get(url2, headers=headers)
if response.status_code == 200:
    json_response = response.json()
    
    # Extracting relevant information
    attributes = json_response.get('data', {}).get('attributes', {})
    stats = attributes.get('last_analysis_stats', {})

    # Extract values with defaults
    analysis_id = json_response.get('data', {}).get('id', 'Not Available')
    scan_date = attributes.get('date', 'Not Available')
    scan_results = attributes.get('last_analysis_results', {})
    malicious = stats.get('malicious', 0)
    harmless = stats.get('harmless', 0)
    suspicious = stats.get('suspicious', 0)
    undetected = stats.get('undetected', 0)
    timeout = stats.get('timeout', 0)
    confirmedtimeout = stats.get('confirmed-timeout', 0)
    failure = stats.get('failure', 0)
    unsupported = stats.get('type-unsupported', 0)
    names = [attributes.get('names', 'Not Available')]

    # Calculate total engines
    total_engines = sum([malicious, harmless, suspicious, undetected, timeout, confirmedtimeout, failure, unsupported])


    print(f"\nAnalysis ID: {analysis_id}")
    print(f"Scan Date: {scan_date}")
    print(f"Total Scan Engines: {total_engines}")
    print(f"Malicious Detections: {malicious}")
    print(f"Harmless Results: {harmless}")
    print(f"Suspicious Results: {suspicious}")
    print(f"Undetected Results: {undetected}")
    print(f"Unsupported Results: {unsupported}")
    
    print("\nDetection Results:")
    for engine, result in scan_results.items():
        if result['category'] == 'malicious':
            print(f"{engine}: {result['category']} - {result['result']}")
        else:
            print(f"{engine}: {result['category']}")
    
    print("\nItem commonly known as: ")
    for name in names:
        print(name)

else:
    print(f"Error: {response.status_code} - {response.text}")

