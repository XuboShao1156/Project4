import sys
from http_req import HttpRequester
from urllib.parse import urlparse

if __name__ == "__main__":
    if len(sys.argv[1:]) != 1:
        print("Invalid command line args: one url is required.")
        exit(1)
    
    url = sys.argv[1]
    urlobj = urlparse(sys.argv[1])
    if urlobj.path == '' or url[-1] == '/':
        url += '/index.html'
    print(url)

    with open(url.split('/')[-1], 'wb') as f:
        f.write(HttpRequester().get(url))
