# encoding: utf-8
import socket
import os
import sys
from utils import *

HOST = "127.0.0.1"
client_port = 21112
BUFSIZ = 1024
SOCK_TIMEOUT = 5

local_hostname = '127.0.0.1'

DEBUG = False

save_stdout = sys.stdout
file_stdout = None

def print_log(string: str):
    print(string, end='\r\n')
    sys.stdout = file_stdout
    print(string, end='\r\n')
    sys.stdout = save_stdout

def socket_send(tsocket, msg, en_recv=True, crlf_deal=0):
    try:
        print_log("C: %s" % msg.replace("\r\n", ""))
        # print_log("C: %s" % msg.replace("\r\n", "\r"))
        msg = ('%s\r\n' % msg).encode('ascii')  
        tsocket.send(msg)
        if en_recv:
            recv_b = tsocket.recv(BUFSIZ)
            if not recv_b:
                raise ConnectionResetError
            try:
                recv = recv_b.decode('ascii')
                recv_list = recv.split("\r\n")
                for i in range(0, len(recv_list)-1):
                    print_log("S: %s" % recv_list[i].replace("\r\n", ""))
                # # if crlf_deal == 0:
                # num = recv.count("\r\n")
                # recv_print = recv.replace(
                #     "\r\n", "\r\nS: ", num-1).replace("\r\n", "")
                # # elif crlf_deal == 1:
                # #     recv_print = recv.replace("\r\n", "<CRLF>")
                # print_log("S: %s" % recv_print)
            except UnicodeDecodeError:
                print(recv_b)
                print("Error! socket receive not ascii byte")
                tsocket.close()
            return recv.strip()     # delete the '\r\n' in the head and back of the string
    except (ConnectionResetError, ConnectionAbortedError):
        print_log("C: Connection lost")
        exit(3)

def main():
    if len(sys.argv) != 2:
        exit(1)
    if DEBUG:
        config_file = "client_configure"
    else:
        config_file = sys.argv[1]
    config_dict = {}
    read_config(config_file, config_dict, 0)
    # client_port = config_dict["client_port"]
    server_port = config_dict["server_port"]
    send_path = config_dict["send_path"]
    global file_stdout
    file_stdout = open("client.log.txt","w")
    first_mail = True
    try:
        for iroot, idirs, ifiles in os.walk(send_path):
            if not idirs:
                for fname in sorted(ifiles):
                    f_full_name = os.path.join(iroot, fname)
                    # print_log("---------------")
                    # print_log(f_full_name)
                    with open(f_full_name, encoding='ascii') as file:
                        flines = file.readlines()
                        f_full_name = os.path.abspath(f_full_name)
                        should_auth = "auth" in f_full_name
                        if len(flines) < 5:
                            print_log("C: %s: Bad formation" % f_full_name)
                            continue
                        # From:
                        tline = flines[0].strip()
                        if len(tline) < 8 or tline[:6] != "From: " or not check_email_with_angle_bracket(tline[6:]):
                            print_log("C: %s: Bad formation" % f_full_name)
                            continue
                        email_from = tline[7:-1]
                        # To:
                        tline = flines[1].strip()
                        if len(tline) < 6 or tline[:4] != "To: ":
                            print_log("C: %s: Bad formation" % f_full_name)
                            continue
                        to_all = tline[4:].strip().split(',')
                        email_to = []
                        for e in to_all:
                            tmp = e.strip()
                            if not check_email_with_angle_bracket(tmp):
                                print_log("C: %s: Bad formation" % f_full_name)
                                continue
                            email_to.append(tmp[1:-1])
                        # Date:
                        tline = flines[2].strip()
                        if len(tline) < 6 or tline[:6] != "Date: ":
                            print_log("C: %s: Bad formation" % f_full_name)
                            continue
                        flines[2] = flines[2].strip()
                        # Subject:
                        tline = flines[3].strip()
                        if len(tline) < 9 or tline[:9] != "Subject: ":
                            print_log("C: %s: Bad formation" % f_full_name)
                            continue
                        flines[3] = flines[3].strip()

                        email_body = flines[2:]  

                        # -----------------------------------
                        # if first_mail:
                        tsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        # tsocket.settimeout(SOCK_TIMEOUT)    
                        # tsocket.bind((HOST, client_port))
                        try:
                            tsocket.connect((HOST, server_port))
                        except (ConnectionResetError, ConnectionAbortedError, ConnectionRefusedError):
                            print_log("C: Cannot establish connection")
                            exit(3)

                        try:
                            recv_b = tsocket.recv(BUFSIZ)
                            if not recv_b:
                                raise ConnectionResetError
                        except ConnectionResetError:
                            print_log("C: Connection lost")
                            exit(3)

                        try:
                            recv = recv_b.decode('ascii')
                            print_log("S: %s" % (recv.replace('\r\n', '')))
                        except UnicodeDecodeError:
                            print(recv_b)
                            print_log("Error! socket receive not ascii byte")
                            tsocket.close()
                            exit(-1)

                        recv = socket_send(tsocket, "EHLO " + local_hostname)
                        if recv[:3] != '250':
                            exit(-1)

                        # TODO AUTH
                        tmp_list = recv.split('\r\n')
                        if should_auth and len(tmp_list) > 1 and tmp_list[1] == "250 AUTH CRAM-MD5":
                            recv = socket_send(tsocket, "AUTH CRAM-MD5")
                            if recv[:3] != '334':
                                exit(-1)
                            recv_str = recv.split(' ')
                            resp_code, challenge = recv_str[0], recv_str[1]
                            if not isBase64(challenge.encode()):
                                # print(challenge)
                                # print("Debug: challenge is not base64 encoded")
                                exit(-1)
                            answer = authentic_answer(challenge)
                            recv = socket_send(tsocket, answer.decode())
                            if recv[:3] != '235':
                                exit(-1)

                        recv = socket_send(tsocket, "MAIL FROM:<%s>" % email_from)
                        if recv[:3] != '250':
                            exit(-1)
                        for receiver in email_to:
                            recv = socket_send(tsocket, "RCPT TO:<%s>" % receiver)
                            if recv[:3] != '250':
                                exit(-1)
                        recv = socket_send(tsocket, "DATA", crlf_deal=1)
                        if recv[:3] != '354':
                            exit(-1)
                        for line in email_body:
                            recv = socket_send(
                                tsocket, line.replace("\n", ""), crlf_deal=1)
                            if recv[:3] != '354':
                                exit(-1)
                        recv = socket_send(tsocket, ".")
                        if recv[:3] != '250':
                            exit(-1)
                        socket_send(tsocket, "QUIT", en_recv=True)
                        tsocket.close()
    except KeyboardInterrupt:
        tsocket.close()
        # first_mail = True
    # if first_mail == False:
    #     socket_send(tsocket, "QUIT")
    #     tsocket.close()
    file_stdout.close()
    # exit(0)


if __name__ == "__main__":
    main()
