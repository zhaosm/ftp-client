import socket
import re

default_server_host = "127.0.0.1"
default_server_port = 21
verbs = ["USER", "PASS", "PORT", "PASV", "RETR", "STOR", "QUIT", "TYPE", "LIST", "CWD", "MKD", "RMD", "SYST"]
MAX_MSG_LENGTH = 9000
my_buffer = ""


def recv_single_msg(sock):
    global my_buffer
    result = my_buffer
    while True:
        search_result = re.search(r"[1-9][0-9]+\s(.*)\r\n", result)
        if search_result:
            end = search_result.end()
            if end < len(result):
                my_buffer = result[end:]
            else:
                my_buffer = ""
            return result[:end]
        result += sock.recv(MAX_MSG_LENGTH)


# def my_sendall(conn, data):
#     n = 0
#     # debug
#     print(len(data))
#     while True:
#         n += conn.send(data[n:])
#         if n == len(data):
#             break


def parse_cmd(cmd):
    cmd_splitted = cmd.split(' ')
    if len(cmd_splitted) == 0:  # no parameters
        verb = cmd_splitted[0]
        parameter = ''
    else:
        verb = cmd_splitted[0]
        parameter = ''.join(cmd_splitted[1:])
        assert verb in verbs, ("Invalid command format: %s." % (cmd))
        # if verb not in verbs:
        #     raise Exception("Invalid command format: %s" % (cmd))
    return verb, parameter


def main():
    try:
        cmd_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        cmd_socket.connect((default_server_host, default_server_port))
        print("Command socket %s." % (str(cmd_socket.getsockname())))
        greeting = recv_single_msg(cmd_socket)  # cmd_socket.recv(MAX_MSG_LENGTH)
        assert greeting.startswith("220 ") and greeting.endswith('\r\n'), "Wrong message from server."
        greeting = greeting[:len(greeting) - 2]
        print("Receive greeting: %s" % (greeting))
        file_socket = None
        mode = 0  # 0 for unset, 1 for PORT, 2 for PASV
        fhost = ""
        fport = -1
        status = 0
        context = {'cmd_socket': cmd_socket, 'file_socket': file_socket, 'mode': mode, 'fhost': fhost, 'fport': fport, 'status': status}
    except Exception as e:
        print(e.message)
        return
    while True:
        try:
            cmd = raw_input("Enter command: ")
            results, context = get_reply(cmd, context)
            for result in results:
                if result['type'] == "reply":
                    reply = result['content']
                    assert reply.endswith('\r\n'), "Wrong reply format."
                    reply = reply[:len(reply) - 2]
                    print("Receive: %s" % (reply))
                else:
                    data = result['content']
                    if data.endswith('\r\n'):
                        data = data[:len(data) - 2]
                    elif data.endswith('\n'):
                        data = data[:len(data) - 1]
                    print("Receive data: %s" % (data))
            if cmd == "QUIT":
                break
        except Exception as e:
            print(e.message)
            continue


def get_reply(cmd, context):
    try:
        verb, parameter = parse_cmd(cmd)
        if verb == "USER":
            assert context['status'] == 0, "USER: Wrong status."
            context['cmd_socket'].sendall("%s %s\r\n" % (verb, parameter))
            reply = recv_single_msg(context['cmd_socket'])
            assert reply.startswith("331 ") and reply.endswith("\r\n"), "USER: Wrong reply from server."
            context['status'] = 1
            return [{"type": "reply", "content": reply}], context
        elif verb == "PASS":
            assert context['status'] == 1, "PASS: Wrong status."
            if context['status'] != 1:
                raise Exception("PASS: Wrong status.")
            context['cmd_socket'].sendall("%s %s\r\n" % (verb, parameter))
            reply = recv_single_msg(context['cmd_socket'])  # context['cmd_socket'].recv(MAX_MSG_LENGTH)
            assert reply.startswith("230") and reply.endswith("\r\n"), "PASS: Error message from server."
            context['status'] = 2
            return [{"type": "reply", "content": reply}], context
        elif context['status'] != 2:
            raise Exception("%s: Wrong status." % (verb))
        if verb == "PORT":  # open new port
            parameter_splitted = parameter.split(',')
            context['fhost'] = '.'.join(parameter_splitted[:4])
            context['fport'] = int(parameter_splitted[4]) * 256 + int(parameter_splitted[5])
            if context['file_socket']:
                print("Closed file socket %s" % (str(context['file_socket'].getsockname())))
                context['file_socket'].close()
                context['file_socket'] = None
            context['mode'] = 1
            context['cmd_socket'].sendall("%s %s\r\n" % (verb, parameter))
            reply = recv_single_msg(context['cmd_socket'])  # context['cmd_socket'].recv(MAX_MSG_LENGTH)
            return [{"type": "reply", "content": reply}], context
        elif verb == "PASV":
            context['cmd_socket'].send("PASV\r\n")
            reply = recv_single_msg(context['cmd_socket'])  # context['cmd_socket'].recv(MAX_MSG_LENGTH)
            addr_splitted = reply.split(' ')[-1].split(',')
            context['fhost'] = '.'.join(addr_splitted[:4])
            context['fport'] = int(addr_splitted[4]) * 256 + int(addr_splitted[5])
            context['mode'] = 2
            return [{'type': 'reply', 'content': reply}], context
        elif verb == "LIST":
            assert context['mode'] == 1 or context['mode'] == 2, "LIST: Need to specify PORT or PASV first."
            if context['file_socket']:
                context['file_socket'].close()
            context['file_socket'] = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            if context['mode'] == 1:  # PORT
                context['file_socket'].bind((context['fhost'], context['fport']))
                context['file_socket'].listen(1)  # only listen to server
            if parameter == "":
                context['cmd_socket'].sendall("LIST\r\n")
            else:
                context['cmd_socket'].sendall("%s %s\r\n" % (verb, parameter))
            reply1 = recv_single_msg(context['cmd_socket'])  # context['cmd_socket'].recv(MAX_MSG_LENGTH)
            assert reply1.startswith("150 ") and reply1.endswith('\r\n'), "LIST: Wrong reply from server."
            if context['mode'] == 1:
                conn, addr = context['file_socket'].accept()
            else:
                context['file_socket'].connect((context['fhost'], context['fport']))
                conn = context['file_socket']
                addr = (context['fhost'], context['fport'])
            print("%s: Connected to %s" % (verb, addr))
            data = ""
            while True:
                new_data = conn.recv(MAX_MSG_LENGTH)
                assert len(new_data) >= 0, "LIST: Error reading from server."
                if len(new_data) == 0:
                    break
                data += new_data
            reply2 = recv_single_msg(context['cmd_socket'])  # context['cmd_socket'].recv(MAX_MSG_LENGTH)
            assert reply2.startswith("226 ") and reply1.endswith('\r\n'), "LIST: Wrong reply from server."
            context['file_socket'].close()
            context['file_socket'] = None
            return [{"type": "reply", "content": reply1}, {"type": "data", "content": data}, {'type': 'reply', 'content': reply2}], context
        elif verb == "RETR":
            assert context['mode'] == 1 or context['mode'] == 2, "RETR: Need to specify PORT or PASV first."
            context['file_socket'] = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            if context['mode'] == 1:  # PORT
                context['file_socket'].bind((context['fhost'], context['fport']))
                context['file_socket'].listen(1)  # only listen to server
            context['cmd_socket'].sendall("%s %s\r\n" % (verb, parameter))
            reply1 = recv_single_msg(context['cmd_socket'])  # context['cmd_socket'].recv(MAX_MSG_LENGTH)
            assert reply1.startswith("150 ") and reply1.endswith('\r\n')
            if context['mode'] == 1:
                conn, addr = context['file_socket'].accept()
            else:
                context['file_socket'].connect((context['fhost'], context['fport']))
                conn = context['file_socket']
                addr = (context['fhost'], context['fport'])
            print("%s: Connected to %s" % (verb, addr))
            data = ""
            while True:
                new_data = conn.recv(MAX_MSG_LENGTH)
                if len(new_data) == 0:
                    break
                data += new_data
            fname = parameter.split('/')[-1]
            with open(fname, "wb") as f:
                f.write(data)
            context['file_socket'].close()
            context['file_socket'] = None
            reply2 = recv_single_msg(context['cmd_socket'])  # context['cmd_socket'].recv(MAX_MSG_LENGTH)
            assert reply2.startswith("226 ") and reply1.endswith('\r\n'), "LIST: Wrong reply from server."
            return [{"type": "reply", "content": reply1}, {'type': 'reply', 'content': reply2}], context
        elif verb == "STOR":  # STOR dest,source
            assert context['mode'] == 1 or context['mode'] == 2, "STOR: Need to specify PORT or PASV first."
            context['file_socket'] = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            if context['mode'] == 1:  # PORT
                context['file_socket'].bind((context['fhost'], context['fport']))
                context['file_socket'].listen(1)  # only listen to server
            fpaths = parameter.split(',')
            context['cmd_socket'].sendall("%s %s\r\n" % (verb, fpaths[0]))
            reply1 = recv_single_msg(context['cmd_socket'])  # context['cmd_socket'].recv(MAX_MSG_LENGTH)
            assert reply1.startswith("150 ") and reply1.endswith('\r\n'), "STOR: Wrong reply from server."
            if context['mode'] == 1:
                conn, addr = context['file_socket'].accept()
            else:
                context['file_socket'].connect((context['fhost'], context['fport']))
                conn = context['file_socket']
                addr = (context['fhost'], context['fport'])
            print("%s: Connected to %s" % (verb, addr))
            with open(fpaths[1], "rb") as f:
                data = f.read()
                conn.sendall(data)
            context['file_socket'].close()
            context['file_socket'] = None
            reply2 = recv_single_msg(context['cmd_socket'])  # context['cmd_socket'].recv(MAX_MSG_LENGTH)
            assert reply2.startswith("226 ") and reply1.endswith('\r\n'), "STOR: Wrong reply from server."
            return [{"type": "reply", "content": reply1}, {"type": "reply", "content": reply2}], context
        elif verb == "MKD" or verb == "CWD" or verb == "RMD":
            context['cmd_socket'].sendall("%s %s\r\n" % (verb, parameter))
            reply = recv_single_msg(context['cmd_socket'])  # context['cmd_socket'].recv(MAX_MSG_LENGTH)
            return [{'type': 'reply', 'content': reply}], context
        elif verb == "TYPE" or verb == "SYST" or verb == "QUIT":
            context['cmd_socket'].sendall("%s\r\n" % (verb))
            reply = recv_single_msg(context['cmd_socket'])  # context['cmd_socket'].recv(MAX_MSG_LENGTH)
            return [{'type': 'reply', 'content': reply}], context
    except Exception as e:
        print(e.message)
        return [], context

main()
