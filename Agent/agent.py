import requests

url = "http://10.160.101.202:5001/ping"

response = requests.get(url)

print("Server Response:", response.json())
