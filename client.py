#!/usr/bin/env python3

import socket
import sys
import re
import ssl

username = sys.argv[-2]
# wang.jiati.
password = sys.argv[-1]
# 4T43I1GBJEAXPRRV.
# The standard (and default) port for HTTP servers to listen on is 80, though they can use any port.
# 443 for an HTTPS URL, and 80 for an HTTP URL.
PORT = 443

hostname = 'project2.5700.network'
URL = 'accounts/login/?next=/fakebook'
visited = []
unvisited = []
secretflag = []

def collectSecretFlag(response):
    pattern = re.compile(r'<h2 class=\'secret_flag\' style=\"color:red\">FLAG: (\w+)</h2>')
    flag = pattern.findall(response)
    print('Page\n' + response)

    if flag:
        secretflag.append(flag)

    print(str(len(secretflag)) + "found" + str(secretflag))


def status(response):
    temp = response.split(" ")
    # print(temp[1])
    return int(temp[1])


def act_on_status(code, response, url):
    response = str(response)
    if code == 302:
        url = "".join(re.findall(r'Location: (.*)', response))
        if url not in unvisited and url not in visited:
            unvisited.append(url)

    if code == 200:
        # print(1)
        anchorLinkPattern = re.compile(r'<a href=\"(/fakebook/[a-z0-9/]+)\">')
        if response.find("FLAG") != -1:
            collectSecretFlag(response)
        links = anchorLinkPattern.findall(response)
        visited.append(url)
        # print(links)
        for link in links:
            if link not in unvisited and link not in visited:
                unvisited.append(link)

    if code == 403 or code == 404 or code == 400:
        if url in unvisited or url in visited:
            unvisited.remove(url)
            visited.remove(url)

    if code == 500 or code == 503 and url not in unvisited:
        unvisited.append(url)


def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, PORT))
    s = ssl.wrap_socket(s, cert_reqs=ssl.CERT_NONE, ca_certs=None)
    get_message = "GET /accounts/login/?next=/fakebook/ HTTP/1.1\r\nHost:" + hostname + "\r\nConnection: " \
                                                                                        "keep-alive\r\n\r\n "
    s.send(get_message.encode('utf-8'))
    response = s.recv(32768).decode('utf-8')
    cookie = re.findall(r'csrftoken=(\w+)', response, re.I)
    # csrfmiddlewaretoken = re.findall(r'csrfmiddlewaretoken = (\w+)', response, re.I)
    csrfmiddlewaretoken = response.find("csrfmiddlewaretoken")
    csrfmiddlewaretoken = str(response[csrfmiddlewaretoken + 28: csrfmiddlewaretoken + 92])
    sessionid = re.findall(r'sessionid=(\w+)', response, re.I)
    cookie = "".join(cookie)

    s.close()

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, PORT))
    s = ssl.wrap_socket(s, cert_reqs=ssl.CERT_NONE, ca_certs=None)
    # post_message = "POST /accounts/login/ HTTP/1.1\r\nHost:" + hostname + "\r\nConnection: keep-alive\r\nCookie:" +
    # str(cookie) + "\r\n\r\n" + "username="+username+"&password="+password+"&csrfmiddlewaretoken
    # ="+csrfmiddlewaretoken+"&next=%2Ffakebook%2F"

    content_type = "Content-type: " + "application/x-www-form-urlencoded\r\n"
    origin = "\r\nOrigin: https://project2.5700.network\r\n"
    post_data = 'username=' + username + '&password=' + password + '&csrfmiddlewaretoken=' + csrfmiddlewaretoken + '&next=%2Ffakebook%2F\r\n'
    post_message = "POST /accounts/login/ HTTP/1.1\r\nHost: project2.5700.network\r\nConnection: " \
                   "keep-alive\r\nContent-Length:" + str(
        len(post_data)) + origin + content_type + "Cookie: csrftoken=" + cookie + "\r\n\r\n" + post_data

    s.send(post_message.encode('utf-8'))
    login_response = s.recv(32768).decode('utf-8')
    # print(login_response)
    s.close()

    cookie = re.findall(r'csrftoken=(\w+)\;', login_response, re.I)

    sessionid = login_response.find("sessionid=")
    sessionid = str(login_response[sessionid + 10: sessionid + 270])

    sessionid = sessionid.split(';')
    sessionid = sessionid[0]

    url = "".join(re.findall(r'Location: (.*)', login_response))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((hostname, PORT))
    s = ssl.wrap_socket(s, cert_reqs=ssl.CERT_NONE, ca_certs=None)
    get_message = "GET /fakebook/ HTTP/1.1\r\nHost: project2.5700.network\r\nConnection: " \
                  "keep-alive\r\nCookie: csrftoken=" + str(cookie) + "; sessionid=" + str(
        sessionid) + "\r\n\r\n" + post_data
    s.send(get_message.encode('utf-8'))
    log_response = s.recv(32768).decode('utf-8')
    print(log_response)

    sessionid = log_response.find("sessionid=")
    sessionid = str(log_response[sessionid + 10: sessionid + 350])
    sessionid = sessionid.split(';')
    sessionid = sessionid[0]

    # print(unvisited, url)
    act_on_status(status(log_response), log_response, url)
    s.close()
    #print(cookie, sessionid)

    while len(secretflag) < 5 and len(unvisited) != 0:
        url = unvisited.pop(0)
        # print(unvisited)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((hostname, PORT))
        s = ssl.wrap_socket(s, cert_reqs=ssl.CERT_NONE, ca_certs=None)
        new_message = "GET " + url + " HTTP/1.1\r\nHost: project2.5700.network\r\nConnection: " \
                                     "keep-alive\r\nCookie: csrftoken=" + str(cookie) + "; sessionid=" + str(
            sessionid) + "\r\n\r\n"

        s.send(new_message.encode('utf-8'))
        temp_response = s.recv(32768).decode('utf-8')

        #print(temp_response)
        act_on_status(status(response), temp_response, url)
        s.close()
        print("secretflag " + str(len(secretflag)) + "sites visited " + str(len(visited)) + "unvisited " + str(len(unvisited)))

if __name__ == "__main__":
    main()
