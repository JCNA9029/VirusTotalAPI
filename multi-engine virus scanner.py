import hashlib
import requests
import pickle
import numpy as np
from pathlib import Path

extension_map = {
    'exe': 1,
    '2exe': 2,
    'dll': 3
 }  
def map_extension_to_number(parameter):
    return extension_map.get(parameter, -1)   
         
def prediction(numeric_value_reshaped):
    with open(r"C:\Users\koala\Desktop\antivirus6", 'rb') as file:
        clf = pickle.load(file)
        pred = clf.predict(numeric_value_reshaped)
        print(pred)
        
def sha256_file(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        #Read the file in chunks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def antivirus():
    file_path = input("Drag the file you want to scan:")

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
        print(f"Error: {response.status_code} - {response.text} \n The file is not yet on the database. Please try again after a few minutes \n Scanning using Machine Learning.")
        parameter = Path(file_path).suffix[1:]
        numeric_value = map_extension_to_number(parameter)
        if parameter not in extension_map:
            print(f"Unknown file extension: {parameter}")
            return -1
        numeric_value_reshaped = np.array([[numeric_value]])
        prediction(numeric_value_reshaped)
        
antivirus()

while True:
    answer = input("\nDo you want to scan another file? Yes (Y) or No (N)?").lower()
    if answer == 'y':
        file_path = None
        antivirus()
    elif answer == 'n':
        print("Thank you for using the app!")
        break
    else: 
        print("Invalid Answer")
        answer