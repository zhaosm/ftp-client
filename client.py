import socket
import re
from Tkinter import *
import ttk
import tkMessageBox
import tkFileDialog
import os

default_server_host = "127.0.0.1"
default_server_port = 21
verbs = ["USER", "PASS", "PORT", "PASV", "RETR", "STOR", "QUIT", "TYPE", "LIST", "CWD", "MKD", "RMD", "SYST"]
MAX_MSG_LENGTH = 9000
my_buffer = ""
default_name_prefix = "/anonymous"


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


def parse_cmd(cmd):  # input command from client without \r\n as end mark
    cmd_splitted = cmd.split(' ')
    if len(cmd_splitted) == 1:  # no parameters
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
        print("Waiting for the server to send greeting message...")
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
            verb, parameter = parse_cmd(cmd)
            results, context = get_reply(verb, parameter, context)
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
                if context['cmd_socket']:
                    context['cmd_socket'].close()
                if context['file_socket']:
                    context['file_socket'].close()
                break
        except Exception as e:
            print(e.message)
            continue


def get_reply(verb, parameter, context):
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
    if verb == "PORT":  # open new port
        assert context['status'] == 2, "PORT: Wrong status."
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
        assert context['status'] == 2, "PASV: Wrong status."
        context['cmd_socket'].send("PASV\r\n")
        reply = recv_single_msg(context['cmd_socket'])  # context['cmd_socket'].recv(MAX_MSG_LENGTH)
        assert reply.startswith("227 ") and reply.endswith("\r\n"), "PASV: Wrong reply from server: %s" % reply
        addr_idx_start = re.match(r'[1-9][0-9]+ (\D*)[0-9]', reply).end() - 1
        addr_idx_end = re.match(r'[1-9][0-9]+ (\D*)[0-9]*,[0-9]*,[0-9]*,[0-9]*,[0-9]*,[0-9]*', reply).end()
        addr_splitted = reply[addr_idx_start:addr_idx_end].split(' ')[-1].split(',')
        context['fhost'] = '.'.join(addr_splitted[:4])
        context['fport'] = int(addr_splitted[4]) * 256 + int(addr_splitted[5])
        context['mode'] = 2
        return [{'type': 'reply', 'content': reply}], context
    elif verb == "LIST":
        assert context['status'] == 2, "LIST: Wrong status."
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
        assert context['status'] == 2, "RETR: Wrong status."
        assert context['mode'] == 1 or context['mode'] == 2, "RETR: Need to specify PORT or PASV first."
        fpaths = parameter.split(',')
        if len(fpaths) == 1:
            fpaths.append(fpaths[0])
        context['file_socket'] = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        if context['mode'] == 1:  # PORT
            context['file_socket'].bind((context['fhost'], context['fport']))
            context['file_socket'].listen(1)  # only listen to server
        context['cmd_socket'].sendall("%s %s\r\n" % (verb, fpaths[1]))
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
        with open(fpaths[0], "wb") as f:
            f.write(data)
        context['file_socket'].close()
        context['file_socket'] = None
        reply2 = recv_single_msg(context['cmd_socket'])  # context['cmd_socket'].recv(MAX_MSG_LENGTH)
        assert reply2.startswith("226 ") and reply1.endswith('\r\n'), "LIST: Wrong reply from server."
        return [{"type": "reply", "content": reply1}, {'type': 'reply', 'content': reply2}], context
    elif verb == "STOR":  # STOR dest,source
        assert context['status'] == 2, "STOR: Wrong status."
        assert context['mode'] == 1 or context['mode'] == 2, "STOR: Need to specify PORT or PASV first."
        context['file_socket'] = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        if context['mode'] == 1:  # PORT
            context['file_socket'].bind((context['fhost'], context['fport']))
            context['file_socket'].listen(1)  # only listen to server
        fpaths = parameter.split(',')
        if len(fpaths) == 1:
            fpaths.append(fpaths[0])
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
    elif verb == "MKD" or verb == "CWD" or verb == "RMD" or verb == "DELE":
        assert context['status'] == 2, "%s: Wrong status." % (verb)
        context['cmd_socket'].sendall("%s %s\r\n" % (verb, parameter))
        reply = recv_single_msg(context['cmd_socket'])  # context['cmd_socket'].recv(MAX_MSG_LENGTH)
        return [{'type': 'reply', 'content': reply}], context
    elif verb == "RNFR":
        assert context['status'] == 2, "%s: Wrong status." % (verb)
        context['cmd_socket'].sendall("%s %s\r\n" % (verb, parameter))
        reply = recv_single_msg(context['cmd_socket'])
        assert reply.startswith("350 ") and reply.endswith("\r\n"), "RNFR: Error message from server."
        context['status'] = 3
        return [{'type': 'reply', 'content': reply}], context
    elif verb == "RNTO":
        assert context['status'] == 3, "RNTO: Wrong server status."
        context['status'] = 2
        context['cmd_socket'].sendall("%s %s\r\n" % (verb, parameter))
        reply = recv_single_msg(context['cmd_socket'])
        assert reply.startswith("250 ") and reply.endswith("\r\n"), "RNTO: Error message from server."
        return [{'type': 'reply', 'content': reply}], context
    elif verb == "TYPE" or verb == "SYST" or verb == "QUIT":
        assert context['status'] == 2, "%s: Wrong status." % (verb)
        context['cmd_socket'].sendall("%s\r\n" % (verb))
        reply = recv_single_msg(context['cmd_socket'])  # context['cmd_socket'].recv(MAX_MSG_LENGTH)
        return [{'type': 'reply', 'content': reply}], context


# GUI
def gui():
    context = {}

    def setServerInfo():
        serverInfoDialog = Tk()
        serverInfoDialog.geometry('480x50+300+300')
        host = StringVar()
        host.set(default_server_host)
        port = StringVar()
        port.set(str(default_server_port))
        hostEntry = Entry(serverInfoDialog, textvariable=host, width=20)
        portEntry = Entry(serverInfoDialog, textvariable=port, width=10)
        hostEntry.grid(row=0, column=0, padx=15, pady=10)
        portEntry.grid(row=0, column=1)

        def submit():
            # global portval
            # global hostval
            # portval = port.get()
            # hostval = host.get()
            global context
            try:
                portval = port.get()
                hostval = host.get()
                cmd_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
                cmd_socket.connect((hostval, int(portval)))
                print("Command socket %s." % (str(cmd_socket.getsockname())))
                print("Waiting for the server to send greeting message...")
                greeting = recv_single_msg(cmd_socket)  # cmd_socket.recv(MAX_MSG_LENGTH)
                assert greeting.startswith("220 ") and greeting.endswith('\r\n'), "Wrong message from server."
                greeting = greeting[:len(greeting) - 2]
                print("Receive greeting: %s" % (greeting))
                file_socket = None
                mode = 0  # 0 for unset, 1 for PORT, 2 for PASV
                fhost = ""
                fport = -1
                status = 0
                context = {'cmd_socket': cmd_socket, 'file_socket': file_socket, 'mode': mode, 'fhost': fhost,
                           'fport': fport, 'status': status, 'port': int(portval), 'host': hostval}
                serverInfoDialog.destroy()
            except Exception as e:
                if e.message == "":
                    message = "Failed to connect to server."
                else:
                    message = e.message
                tkMessageBox.showinfo("Error", message)
                context = {}
                serverInfoDialog.destroy()
                setServerInfo()
                return
            login()

        def cancel():
            serverInfoDialog.destroy()
        OKButton = Button(serverInfoDialog, command=submit, text="OK")
        OKButton.grid(row=0, column=2)
        cancelButton = Button(serverInfoDialog, command=cancel, text="Cancel")
        cancelButton.grid(row=0, column=3)
        serverInfoDialog.mainloop()

    def login():
        loginDialog = Tk()
        loginDialog.geometry('480x50+300+300')
        username = StringVar()
        username.set('anonymous')
        password = StringVar()
        password.set('anonymous@mails.tsinghua.edu.cn')
        usernameEntry = Entry(loginDialog, textvariable=username, text="Username")
        passwordEntry = Entry(loginDialog, textvariable=password, text="Password")
        usernameEntry.grid(row=0, column=0, padx=15, pady=10)
        passwordEntry.grid(row=0, column=1)

        def submit():
            global context
            context['username'] = username.get()
            context['password'] = password.get()
            loginDialog.destroy()
            results, context = get_reply("USER", context['username'], context)
            results, context = get_reply("PASS", context['password'], context)
            go()

        def cancel():
            global context
            context = {}
            loginDialog.destroy()
            setServerInfo()
        OKButton = Button(loginDialog, command=submit, text="OK")
        OKButton.grid(row=0, column=2)
        cancelButton = Button(loginDialog, command=cancel, text="Cancel")
        cancelButton.grid(row=0, column=3)
        loginDialog.mainloop()

    def go():
        window = Tk()
        try:
            global context
            window.geometry('800x500+200+100')
            tree = ttk.Treeview(window, selectmode="extended", height=22)
            tree.heading("#0", text="Name")
            tree.column("#0", width=800, stretch=True)
            tree.grid(row=1, column=0, padx=8, columnspan=12)
            tree.pack()
            menu_bar = Menu(window, tearoff=False)

            # def my_see(path):  # show all stuff under this dir, and unfold all ancestors of this dir
            #     dir_names = path.split('/')
            #     dlen = len(dir_names)
            #     next_dir_idd = show_dir('', '/', dir_names[0])
            #     for i in range(dlen - 1):
            #         next_dir_idd = show_dir(next_dir_idd, '/'.join(dir_names[:i + 1]), dir_names[i + 1])
            #     show_dir(next_dir_idd, path, '')

            def build_dir(path):  # path: path from root dir, use path+type as iid
                global context
                results, context = get_reply("PASV", "", context)
                results, context = get_reply("LIST", path, context)
                data = ""
                for result in results:
                    if result['type'] == 'data':
                        data = result['content']
                data_splitted = data.split('\n')
                data_splitted = data_splitted[:len(data_splitted) - 1]
                fnum = len(data_splitted)
                for i in range(1, fnum):
                    fdata = data_splitted[i].split(' ')
                    info = {'name': fdata[-1]}
                    iid = os.path.join(path, info['name'])
                    # if path == '/':
                    #     iid = path + info['name']
                    # else:
                    #     iid = path + '/' + info['name']
                    if fdata[0].startswith('d'):
                        info['type'] = 'd'
                        iid += info['type']
                        tree.insert(path + 'd', 'end', iid=iid, tags=info['type'], text=info['name'])
                        build_dir(iid[:len(iid) - 1])
                    else:
                        info['type'] = 'f'
                        iid += info['type']
                        tree.insert(path + 'd', 'end', iid=iid, tags=info['type'], text=info['name'])

            def on_right_click(event):
                global context
                iid = tree.identify_row(event.y)
                if iid == "":  # didn't select a dir
                    return
                try:
                    item = tree.item(iid)
                except:
                    return
                tree.selection_set(iid)

                def download():
                    global context
                    filepath = tkFileDialog.asksaveasfilename()
                    if not isinstance(filepath, str):
                        return
                    results, context = get_reply("PASV", "", context)
                    results, context = get_reply("RETR", "%s,%s" % (filepath, iid[:len(iid) - 1]), context)

                def upload():
                    global context
                    filepath = tkFileDialog.askopenfilename()
                    if not isinstance(filepath, str):
                        return
                    results, context = get_reply("PASV", "", context)
                    fname = filepath.split('/')[-1]
                    fpath_server = iid[:len(iid) - 1] + '/' + fname
                    results, context = get_reply("STOR", "%s,%s" % (fpath_server, filepath), context)
                    fiid = fpath_server + 'f'
                    try:
                        tree.item(fiid)
                    except:
                        tree.insert(iid, 'end', tags=fiid[-1], iid=fiid, text=fname)
                    tree.see(fiid)
                    tree.selection_set(fiid)

                def delete():
                    if iid == "/d":
                        tkMessageBox.showinfo("Error", "You don't have privilege to delete the root folder.")
                        return
                    global context
                    if iid.endswith('d'):
                        results, context = get_reply("RMD", iid[:len(iid) - 1], context)
                    else:
                        results, context = get_reply("DELE", iid[:len(iid) - 1], context)
                    tree.delete(iid)

                def rename():
                    if iid == "/d":
                        tkMessageBox.showinfo("Error", "You don't have privilege to rename the root folder.")
                        return
                    parentiid = tree.parent(iid)

                    get_dest_name_dialog = Tk()
                    get_dest_name_dialog.geometry('480x50+300+300')
                    dest = StringVar()
                    destEntry = Entry(get_dest_name_dialog, textvariable=dest, text="New name")
                    destEntry.grid(row=0, column=0, padx=15, pady=10)

                    def submit():
                        new_name = destEntry.get()
                        get_dest_name_dialog.destroy()
                        type = iid[-1]
                        new_iid = os.path.join(parentiid[:len(parentiid) - 1], new_name) + type
                        global context
                        results, context = get_reply("RNFR", iid[:len(iid) - 1], context)
                        results, context = get_reply("RNTO", new_iid[:len(new_iid) - 1], context)
                        index = tree.index(iid)
                        tree.delete(iid)
                        tree.insert(parentiid, index, tags=new_iid[-1], iid=new_iid, text=new_name)
                        build_dir(new_iid[:len(new_iid) - 1])
                        tree.selection_set(new_iid)

                    def cancel():
                        get_dest_name_dialog.destroy()

                    ok_button = Button(get_dest_name_dialog, command=submit, text="OK")
                    ok_button.grid(row=0, column=2)
                    cancel_button = Button(get_dest_name_dialog, command=cancel, text="Cancel")
                    cancel_button.grid(row=0, column=3)
                    get_dest_name_dialog.mainloop()

                def create():
                    get_new_dir_name_dialog = Tk()
                    get_new_dir_name_dialog.geometry('480x50+300+300')
                    new_dir_name = StringVar()
                    newDirNameEntry = Entry(get_new_dir_name_dialog, textvariable=new_dir_name, text="Name")
                    newDirNameEntry.grid(row=0, column=0, padx=15, pady=10)

                    def submit():
                        new_name = newDirNameEntry.get()
                        get_new_dir_name_dialog.destroy()
                        new_dir_path = os.path.join(iid[:len(iid) - 1], new_name)
                        global context
                        results, context = get_reply("MKD", new_dir_path, context)
                        new_iid = new_dir_path + 'd'
                        tree.insert(iid, 0, tags=new_iid[-1], iid=new_iid, text=new_name)
                        tree.see(new_iid)
                        tree.selection_set(new_iid)

                    def cancel():
                        get_new_dir_name_dialog.destroy()

                    ok_button = Button(get_new_dir_name_dialog, command=submit, text="OK")
                    ok_button.grid(row=0, column=2)
                    cancel_button = Button(get_new_dir_name_dialog, command=cancel, text="Cancel")
                    cancel_button.grid(row=0, column=3)
                    get_new_dir_name_dialog.mainloop()

                menu_bar.delete(0, END)
                menu_bar.post(event.x_root, event.y_root)
                if iid.endswith('d'):  # dir
                    menu_bar.add_command(label="Upload", command=upload)
                    menu_bar.add_command(label="Create dir", command=create)
                else:
                    menu_bar.add_command(label="Download", command=download)
                menu_bar.add_command(label="Rename", command=rename)
                menu_bar.add_command(label="Delete", command=delete)

            def on_left_click(event):
                menu_bar.delete(0, END)

            tree.insert('', 'end', iid='/d', tags='d', text='/')
            build_dir('/')
            tree.see(default_name_prefix + 'd')
            tree.selection_set(default_name_prefix + "d")
            tree.bind("<Button-3>", on_right_click)
            tree.bind("<Button-1>", on_left_click)
            tree.tag_configure('d', foreground='blue')

            window.mainloop()
        except Exception as e:
            tkMessageBox.showinfo("Error", e.message)
            context = {}
            window.destroy()
            setServerInfo()

    setServerInfo()

gui()