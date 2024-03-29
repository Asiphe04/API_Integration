import requests
import datetime
from requests.auth import HTTPBasicAuth
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
opensearch_url = "https://dev.armada247.com:55000"
wazuh_username = "wazuh-wui"
wazuh_password = "MyS3cr37P450r.*-"
record_file_path = "document_count_record.txt"
index_prefix = "wazuh-alerts-4.x-"
tenant_id = "dev"

# def get_auth_token():
#     try:
 
#       response = requests.post(
#             f"{opensearch_url}/security/user/authenticate?raw=true",
#             auth=HTTPBasicAuth(wazuh_username, wazuh_password),
#             verify=False
#         )
#       if response.status_code == 200:
#             try:
#                 event_body = response.json()
#                 return response.status_code, event_body
#             except ValueError:
#                 print("Response body is not in valid JSON format.")
#                 return response.status_code, None
#       else:
#             print(f"Error getting auth token {response.status_code}")
#             return response.status_code, None
#     except Exception as e:
#         print(f"Error getting auth token: {e}") 
#         return None, None

def get_auth_token(wazuh_username, wazuh_password):
    url = "https://dev.armada247.com:55000/security/user/authenticate?raw=true"
    response = requests.get(url, auth=(wazuh_username,  wazuh_password), verify=False)
    response.raise_for_status()  # Check if request was successful
    print(response.text)
    return response.text
    
    

def post_security_events(token):
    try:
      payload =   {
        "events": [
         "Event value 1",
         "{\"someKey\": \"Event value 2\"}"
        ]
      }
      # payload = {
      #         "timestamp": "2024-03-12T12:00:00Z",
      #       "event": "Dummy Event",
      #       "description": "This is a dummy event for testing purposes."
      # } 
      headers = {
        "Authorization": f"Bearer {token}"
     }
      
      response = requests.post(
            f"{opensearch_url}/events",
            headers=headers,
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
    
    token = get_auth_token(wazuh_username, wazuh_password)


    status_code, event_body = post_security_events(token)
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
