import requests
#replace the sha with the sha of the file you want to scan. Below is an example
sha = "4d823224916b1be918a2eeb5035c780d352fa6a45fe0e993bb0dd6f5d1059849"
url = "https://www.virustotal.com/api/v3/files/" + sha

headers = {
    "accept": "application/json",
    #insert your own API. Below is my own API PLS DONT USE/SPREAD IT 
    "x-apikey": "acf09e97046fd748b4cdc5a9cd2a53d6da2ca56d57eb8602f9e0374146ad78a3"
}

response = requests.get(url, headers=headers)
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

else:
    print(f"Error: {response.status_code} - {response.text}")