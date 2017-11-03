import socket
import re
from Tkinter import *
import ttk
import tkMessageBox
import tkFileDialog
import os

default_server_host = "127.0.0.1"
default_server_port = 21
verbs = ["USER", "PASS", "PORT", "PASV", "RETR", "STOR", "QUIT", "TYPE", "LIST", "CWD", "MKD", "RMD", "SYST", "DELE", "RNFR", "RNTO", "ABOR"]
MAX_MSG_LENGTH = 9000
my_buffer = ""
default_name_prefix = "/"


def recv_single_msg(sock):
    # read from server through sock until a complete message is received
    # then put remained data in buffer and return the message
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


def parse_cmd(cmd):  # cmd: input command from client without \r\n as end mark
    cmd_splitted = cmd.split(' ')
    if len(cmd_splitted) == 1:  # no parameters
        verb = cmd_splitted[0]
        parameter = ''
    else:
        verb = cmd_splitted[0]
        parameter = ''.join(cmd_splitted[1:])
        assert verb in verbs, ("Invalid command format: %s." % (cmd))
    return verb, parameter


def command(h, p):
    # command line version
    # read commands from user through standard input and send message to server
    # then output replies from server
    # if Exception occurred or received error message from server, info the user and ask for new command
    # exit when user entered QUIT or ABOR
    global my_buffer
    try:
        cmd_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        cmd_socket.connect((h, int(p)))
        print("Command socket %s." % (str(cmd_socket.getsockname())))
        print("Waiting for the server to send greeting message...")
        greeting = recv_single_msg(cmd_socket)
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
            if cmd == "QUIT" or cmd == "ABOR":
                if context['cmd_socket']:
                    context['cmd_socket'].close()
                if context['file_socket']:
                    context['file_socket'].close()
                break
        except Exception as e:
            print(e)
            my_buffer = ""
            # ensure context mode reset
            context['mode'] = 0
            if context['status'] == 3:
                context['status'] = 2
            if context['file_socket']:
                context['file_socket'].close()
            continue


def get_reply(verb, parameter, context):
    # context includes user status, transmitting mode, sockets info, etc.
    # handle user commands, return replies and new context
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
        reply = recv_single_msg(context['cmd_socket'])
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
        reply = recv_single_msg(context['cmd_socket'])
        assert reply.startswith("200 ") and reply.endswith("\r\n"), "Wrong reply from server: %s." % reply
        return [{"type": "reply", "content": reply}], context
    elif verb == "PASV":
        assert context['status'] == 2, "PASV: Wrong status."
        context['cmd_socket'].send("PASV\r\n")
        reply = recv_single_msg(context['cmd_socket'])
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

        # ensure file socket closed
        if context['file_socket']:
            context['file_socket'].close()
        context['file_socket'] = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        if context['mode'] == 1:  # PORT
            context['file_socket'].bind((context['fhost'], context['fport']))
            context['file_socket'].listen(1)  # only listen to server

        # send command
        if parameter == "":
            context['cmd_socket'].sendall("LIST\r\n")
        else:
            context['cmd_socket'].sendall("%s %s\r\n" % (verb, parameter))
        # establish connection
        if context['mode'] == 1:  # PORT
            conn, addr = context['file_socket'].accept()
        else:
            context['file_socket'].connect((context['fhost'], context['fport']))
            conn = context['file_socket']
            addr = (context['fhost'], context['fport'])
        print("%s: Connected to %s" % (verb, addr))

        # get 150 mark
        reply1 = recv_single_msg(context['cmd_socket'])
        assert reply1.startswith("150 ") and reply1.endswith('\r\n'), "LIST: Wrong reply from server %s." % (reply1)
        # read
        data = ""
        while True:
            try:
                new_data = conn.recv(MAX_MSG_LENGTH)
                if len(new_data) == 0:
                    break
                data += new_data
            except:
                break
        # get success message
        reply2 = recv_single_msg(context['cmd_socket'])
        assert reply2.startswith("226 ") and reply1.endswith('\r\n'), "LIST: Wrong reply from server."
        if context['mode'] == 1:
            conn.close()
        # ensure context mode reset before return
        context['file_socket'].close()
        context['file_socket'] = None
        context['mode'] = 0
        return [{"type": "reply", "content": reply1}, {"type": "data", "content": data}, {'type': 'reply', 'content': reply2}], context
    elif verb == "RETR":
        assert context['status'] == 2, "RETR: Wrong status."
        assert context['mode'] == 1 or context['mode'] == 2, "RETR: Need to specify PORT or PASV first."
        assert parameter != '', "RETR: You should specify file path."

        if context['file_socket']:
            context['file_socket'].close()
        context['file_socket'] = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        if context['mode'] == 1:  # PORT
            context['file_socket'].bind((context['fhost'], context['fport']))
            context['file_socket'].listen(1)  # only listen to server

        fpaths = parameter.split(',')
        if len(fpaths) == 1:
            fpaths.append(fpaths[0])
        context['cmd_socket'].sendall("%s %s\r\n" % (verb, fpaths[1]))

        if context['mode'] == 1:  # PORT
            conn, addr = context['file_socket'].accept()
        else:
            context['file_socket'].connect((context['fhost'], context['fport']))
            conn = context['file_socket']
            addr = (context['fhost'], context['fport'])
        print("%s: Connected to %s" % (verb, addr))

        reply1 = recv_single_msg(context['cmd_socket'])
        assert reply1.startswith("150 ") and reply1.endswith('\r\n')

        data = ""
        while True:
            try:
                new_data = conn.recv(MAX_MSG_LENGTH)
                if len(new_data) == 0:
                    break
                data += new_data
            except:
                break
        conn.close()

        with open(fpaths[0], "wb") as f:
            f.write(data)

        if context['mode'] == 1:
            context['file_socket'].close()
        context['file_socket'] = None
        reply2 = recv_single_msg(context['cmd_socket'])
        assert reply2.startswith("226 ") and reply2.endswith('\r\n'), "RETR: Wrong reply from server."
        context['mode'] = 0
        return [{"type": "reply", "content": reply1}, {'type': 'reply', 'content': reply2}], context
    elif verb == "STOR":  # STOR dest,source or STOR fname
        assert context['status'] == 2, "STOR: Wrong status."
        assert context['mode'] == 1 or context['mode'] == 2, "STOR: Need to specify PORT or PASV first."
        assert parameter != '', "You should specify file path."

        if context['file_socket']:
            context['file_socket'].close()
        context['file_socket'] = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        if context['mode'] == 1:  # PORT
            context['file_socket'].bind((context['fhost'], context['fport']))
            context['file_socket'].listen(1)  # only listen to server

        fpaths = parameter.split(',')
        if len(fpaths) == 1:
            fpaths.append(fpaths[0])
        with open(fpaths[1], "rb") as f:
            data = f.read()

        context['cmd_socket'].sendall("%s %s\r\n" % (verb, fpaths[0]))
        if context['mode'] == 1:  # PORT
            conn, addr = context['file_socket'].accept()
        else:
            context['file_socket'].connect((context['fhost'], context['fport']))
            conn = context['file_socket']
            addr = (context['fhost'], context['fport'])
        print("%s: Connected to %s" % (verb, addr))

        reply1 = recv_single_msg(context['cmd_socket'])
        assert reply1.startswith("150 ") and reply1.endswith('\r\n'), "STOR: Wrong reply from server."

        conn.sendall(data)
        conn.close()
        if context['mode'] == 1:
            context['file_socket'].close()
        context['file_socket'] = None

        reply2 = recv_single_msg(context['cmd_socket'])
        assert reply2.startswith("226 ") and reply2.endswith('\r\n'), "STOR: Wrong reply from server."
        context['mode'] = 0
        return [{"type": "reply", "content": reply1}, {"type": "reply", "content": reply2}], context
    elif verb == "MKD" or verb == "CWD" or verb == "RMD" or verb == "DELE":
        assert context['status'] == 2, "%s: Wrong status." % (verb)
        context['cmd_socket'].sendall("%s %s\r\n" % (verb, parameter))
        reply = recv_single_msg(context['cmd_socket'])
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
    elif verb == "TYPE":
        assert context['status'] == 2, "%s: Wrong status." % (verb)
        context['cmd_socket'].sendall("%s %s\r\n" % (verb, parameter))
        reply = recv_single_msg(context['cmd_socket'])
        return [{'type': 'reply', 'content': reply}], context
    elif verb == "SYST":
        assert context['status'] == 2, "%s: Wrong status." % (verb)
        context['cmd_socket'].sendall("%s\r\n" % (verb))
        reply = recv_single_msg(context['cmd_socket'])
        return [{'type': 'reply', 'content': reply}], context
    elif verb == "QUIT" or verb == "ABOR":
        context['cmd_socket'].sendall("%s\r\n" % (verb))
        reply = recv_single_msg(context['cmd_socket'])
        return [{'type': 'reply', 'content': reply}], context


def gui():
    # gui version
    context = {}

    def setServerInfo():
        # set host and port
        serverInfoDialog = Tk()
        serverInfoDialog.title('Enter host and port')
        serverInfoDialog.geometry('500x50')
        host = StringVar()
        host.set(default_server_host)
        port = StringVar()
        port.set(str(default_server_port))
        hostEntry = Entry(serverInfoDialog, textvariable=host, width=20, text="host")
        portEntry = Entry(serverInfoDialog, textvariable=port, width=16, text="port")
        hostEntry.grid(row=0, column=0, padx=10, pady=10)
        portEntry.grid(row=0, column=1)

        def submit():
            global context
            try:
                portval = port.get()
                hostval = host.get()
                cmd_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
                cmd_socket.connect((hostval, int(portval)))
                print("Command socket %s." % (str(cmd_socket.getsockname())))
                print("Waiting for the server to send greeting message...")
                greeting = recv_single_msg(cmd_socket)
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
                tkMessageBox.showinfo("Error", e)
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

    def setPortInfo():
        setPortInfoDialog = Tk()
        setPortInfoDialog.title('Set host and port for PORT mode')
        host = StringVar()
        port = StringVar()
        hostEntry = Entry(setPortInfoDialog, textvariable=host, width=20, text="Host")
        portEntry = Entry(setPortInfoDialog, textvariable=port, width=16, text="Port")
        hostEntry.grid(row=0, column=0, padx=10, pady=10)
        portEntry.grid(row=0, column=1)

        def submit():
            global context
            global my_buffer
            host_str = ','.join(str(hostEntry.get()).split('.'))
            port_int = int(portEntry.get())
            p1 = port_int / 256
            p2 = port_int % 256
            param = host_str + ',' + str(p1) + ',' + str(p2)
            old_context = context
            try:
                result, context = get_reply("PORT", param, context)
            except Exception as e:
                context = old_context
                my_buffer = ""
                tkMessageBox.showinfo("Error", e)
                setPortInfoDialog.destroy()
        def cancel():
            setPortInfoDialog.destroy()

        OKButton = Button(setPortInfoDialog, command=submit, text="OK")
        OKButton.grid(row=0, column=2)
        cancelButton = Button(setPortInfoDialog, command=cancel, text="Cancel")
        cancelButton.grid(row=0, column=3)
        setPortInfoDialog.mainloop()


    def login():
        # send username and password
        loginDialog = Tk()
        loginDialog.title('Login')
        loginDialog.geometry('650x50')
        username = StringVar()
        username.set('anonymous')
        password = StringVar()
        password.set('anonymous@mails.tsinghua.edu.cn')
        usernameEntry = Entry(loginDialog, textvariable=username, width=20, text="Username")
        passwordEntry = Entry(loginDialog, textvariable=password, width=16, text="Password")
        usernameEntry.grid(row=0, column=0, padx=10, pady=10)
        passwordEntry.grid(row=0, column=1)
        m = IntVar()
        m.set(2)
        rb_pasv = Radiobutton(loginDialog, text="PASV", variable=m, value=2)
        rb_port = Radiobutton(loginDialog, text="PORT", variable=m, value=1)
        rb_pasv.grid(row=0, column=2)
        rb_port.grid(row=0, column=3)

        def submit():
            global context
            context['username'] = username.get()
            context['password'] = password.get()
            context['mode'] = int(m.get())
            # debug
            # print("Mode: %d." % mode_value)

            loginDialog.destroy()
            try:
                results, context = get_reply("USER", context['username'], context)
                results, context = get_reply("PASS", context['password'], context)
            except Exception as e:
                if e.message == "":
                    message = "Failed to login."
                else:
                    message = e.message
                tkMessageBox.showinfo("Error", message)
                return
            go()

        def cancel():
            global context
            context = {}
            loginDialog.destroy()
            setServerInfo()
        OKButton = Button(loginDialog, command=submit, text="OK")
        OKButton.grid(row=0, column=4)
        cancelButton = Button(loginDialog, command=cancel, text="Cancel")
        cancelButton.grid(row=0, column=5)
        loginDialog.mainloop()

    def go():
        # show the working directory using a ttk.Treeview object
        # users are able to modify dir/file by right-clicking dir/file's row
        window = Tk()
        window.title('FTP Client')
        global context
        window.geometry('800x600')
        tree = ttk.Treeview(window, selectmode="extended", height=29, columns=("one", "two"))
        tree.heading("#0", text="Name")
        tree.column("#0", width=280, stretch=True)
        tree.column("one", width=280)
        tree.heading("one", text="Modify time")
        tree.column("two", width=280)
        tree.heading("two", text="Size")
        tree.grid(row=1, column=0, padx=8, columnspan=12)
        tree.pack()
        menu_bar = Menu(window, tearoff=False)

        def build_dir(path):
            # path: path from root dir, use path+type as iid
            # show all contents under path recursively
            global context
            results, context = get_reply("PASV", "", context)
            results, context = get_reply("LIST", path, context)
            data = ""
            for result in results:
                if result['type'] == 'data':
                    data = result['content']
            data_splitted = data.split('\n')
            data_splitted = data_splitted[:len(data_splitted) - 1]
            if data_splitted[0].startswith("total") or data_splitted[0].startswith("Total"):
                data_splitted = data_splitted[1:]
            fnum = len(data_splitted)
            for i in range(1, fnum):
                fdata = data_splitted[i].split()
                info = {'name': fdata[-1], 'time': ' '.join([fdata[-4], fdata[-3], fdata[-2]]), 'size': fdata[-5] + "B"}
                iid = os.path.join(path, info['name'])
                if fdata[0].startswith('d'):
                    info['type'] = 'd'
                    iid += info['type']
                    tree.insert(path + 'd', 'end', iid=iid, tags=info['type'], text=info['name'], values=(info['time'], info['size']))
                    build_dir(iid[:len(iid) - 1])
                else:
                    info['type'] = 'f'
                    iid += info['type']
                    tree.insert(path + 'd', 'end', iid=iid, tags=info['type'], text=info['name'], values=(info['time'], info['size']))

        def get_info(path, type):
            # get information of a dir/file specified by path and type
            global context
            path_splitted = path.split('/')
            name = path_splitted[-1]
            parent_path = '/'.join(path_splitted[:len(path_splitted) - 1])
            if parent_path == '':
                parent_path = '/'
            try:
                results, context = get_reply("PASV", "", context)
                results, context = get_reply("LIST", parent_path, context)
                for result in results:
                    if result['type'] == 'data':
                        info = {}
                        result_splitted = result['content'].split('\n')
                        if result_splitted[0].startswith("total") or result_splitted[0].startswith("Total"):
                            result_splitted = result_splitted[1:]
                        result_splitted = result_splitted[:len(result_splitted) - 1]
                        for line in result_splitted:
                            infos = line.split()
                            if ((type == "d" and infos[0].startswith('d')) or (type == 'f' and not infos[0].startswith('d'))) and infos[-1] == name:
                                info['type'] = type
                                info['name'] = infos[-1]
                                info['time'] = ' '.join([infos[-4], infos[-3], infos[-2]])
                                info['size'] = infos[-5]
                                return info
            except Exception as e:
                tkMessageBox.showinfo("Error", e)

        def on_right_click(event):
            # show buttons to modify file/dir
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
                fpath_server = os.path.join(iid[:len(iid) - 1], fname)
                results, context = get_reply("STOR", "%s,%s" % (fpath_server, filepath), context)
                fiid = fpath_server + 'f'
                try:
                    tree.item(fiid)
                except:
                    tree.insert(iid, 'end', tags=fiid[-1], iid=fiid, text=fname)
                info = get_info(fiid[:len(fiid) - 1], fiid[-1])
                tree.item(fiid, values=(info['time'], info['size']))
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
                    info = get_info(new_iid[:len(new_iid) - 1], new_iid[-1])
                    tree.item(new_iid, values=(info['time'], info['size']))
                    tree.see(new_iid)
                    tree.selection_set(new_iid)

                def cancel():
                    get_new_dir_name_dialog.destroy()

                ok_button = Button(get_new_dir_name_dialog, command=submit, text="OK")
                ok_button.grid(row=0, column=2)
                cancel_button = Button(get_new_dir_name_dialog, command=cancel, text="Cancel")
                cancel_button.grid(row=0, column=3)
                get_new_dir_name_dialog.mainloop()

            # when right button clicked, clear menu bar and show a new one at the position user clicked
            menu_bar.delete(0, END)
            if iid.endswith('d'):  # dir
                menu_bar.add_command(label="Upload", command=upload)
                menu_bar.add_command(label="Create dir", command=create)
            else:
                menu_bar.add_command(label="Download", command=download)
            menu_bar.add_command(label="Rename", command=rename)
            menu_bar.add_command(label="Delete", command=delete)
            menu_bar.post(event.x_root, event.y_root)

        def on_left_click(event):
            # when left-clicked, clear the menu bar
            menu_bar.delete(0, END)

        def set_mode(event):
            global context
            old_context = context
            if context['mode'] == 2:  # try change to PORT
                setPortInfo()
                mode_bn.config("change to PASV")
            else:
                try:
                    result, context = get_reply("PASV", "", context)
                    mode_bn.config("change to PORT")
                except Exception as e:
                    context = old_context
                    tkMessageBox.showinfo("Error", e)

        # build root dir
        tree.insert('', 'end', iid='/d', tags='d', text='/')
        build_dir('/')
        tree.see(default_name_prefix + 'd')
        tree.selection_set(default_name_prefix + "d")
        tree.bind("<Button-2>", on_right_click)
        tree.bind("<Button-1>", on_left_click)
        tree.tag_configure('d', foreground='blue')

        mode_bn = Button(window, command=set_mode)
        mode_bn.grid(row=31, column=0)
        if context['mode'] == 1:
            mode_bn.config(text="change to PASV")
        else:
            mode_bn.config(text="change to PORT")

        window.mainloop()

    setServerInfo()

if __name__ == '__main__':
    if sys.argv[1] == 'gui':
        gui()
    elif sys.argv[1] == 'command':
        h = default_server_host
        p = default_server_port
        argvs = sys.argv
        for i, arg in enumerate(sys.argv):
            if arg == '-host' and i < len(sys.argv) - 1:
                h = sys.argv[i + 1]
            elif arg == '-port' and i < len(sys.argv) - 1:
                p = sys.argv[i + 1]
        command(h, p)