import sys
from http_req import HttpRequester
from urllib.parse import urlparse

if __name__ == "__main__":
    if len(sys.argv[1:]) != 1:
        print("Invalid command line args: one url is required.")
        exit(1)

    url = sys.argv[1]
    code, content = HttpRequester().get(url)

    if code == 200:
        urlobj = urlparse(sys.argv[1])

        fn = url.split('/')[-1]
        if urlobj.path == '':
            fn = 'index.html'
        if url[-1] == '/':
            fn = 'index.html'
        print(fn)

        with open(fn, 'wb') as f:
            f.write(content)
    else:
        print('Error: response code {}!'.format(code))
