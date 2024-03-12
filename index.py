import requests
import datetime
from requests.auth import HTTPBasicAuth
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
opensearch_url = "https://demo.armada247.com:55000"
wazuh_username = "wazuh-wui"
wazuh_password = "MyS3cr37P450r.*-"
record_file_path = "document_count_record.txt"
index_prefix = "wazuh-alerts-4.x-"
tenant_id = "demo"

def post_security_events():
    try:
        payload = {
            "time": "2024-03-12T10:28:42.141Z",
            #"event": "Dummy Event",
            "description": "This is a dummy event for testing purposes."
        }
        response = requests.post(
            f"{opensearch_url}/security/user/authenticate?raw=true",
            auth=HTTPBasicAuth(wazuh_username, wazuh_password),
            json=payload,
            verify=False
        )
        if response.status_code == 200:
            try:
                event_body = response.json()
                return response.status_code, event_body
            except ValueError:
                print("Response body is not in valid JSON format.")
                return response.status_code, None
        else:
            print(f"Error posting Security Event: HTTP {response.status_code}")
            return response.status_code, None
    except Exception as e:
        print(f"Error posting Security Event: {e}")
        return None, None

def main():   
    status_code, event_body = post_security_events()
    if status_code:    
        print(f"Response Status Code: {status_code}")
        if event_body:
            print(f"Event Body: {event_body}")
        else:
            print("No event body returned.")
    else:
        print("Error posting security event.")

if __name__ == "__main__":
    main()
