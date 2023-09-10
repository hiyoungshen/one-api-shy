import requests

url = "http://10.129.162.8:3002/"
query = {"url" : "http://wjpython.openjudge.cn/2022fallpractice/solution/36305828/"}
response = requests.post(url, json=query)

if response.status_code == 200:
    results = response.json()
    print("Result:", results)
else:
    print("Error:", response.text)