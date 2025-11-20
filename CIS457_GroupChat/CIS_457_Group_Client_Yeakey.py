import tkinter as tk
from tkinter import simpledialog, scrolledtext
import threading
import socket
import queue

class App:
    def __init__(self, master):
        self.master = master
        master.withdraw()

        self.userName = simpledialog.askstring("Name Request", "Enter your name:")
        if self.userName:
            master.title("Client " + self.userName)
            master.deiconify()
        else:
            master.destroy()
            return

        self.selfMessage = False

        self.message_frame = scrolledtext.ScrolledText(master, wrap=tk.WORD, state='disabled', height=10)
        self.message_frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        self.message_frame.tag_config("self_message", foreground="green")
        self.message_frame.tag_config("not_self_message", foreground="black")


        self.input_box = tk.Text(master, height=2)#, width=30)
        self.input_box.pack()

        self.submit_button = tk.Button(master, text="Send Message", command=self.on_submit)
        self.submit_button.pack()

        self.data_queue = queue.Queue()
        self.running = True

        self.socket_thread = threading.Thread(target=self.read_socket)
        self.socket_thread.daemon = True  # Allow program to exit even if thread is running
        self.socket_thread.start()

        self.update_gui()

    def on_submit(self):
        text = self.input_box.get("1.0", "end-1c")
        self.selfMessage = True
        self.data_queue.put(text)
        self.s.sendall((self.userName + ": " + text).encode())
        self.input_box.delete("1.0", tk.END)

    def read_socket(self):
        host = '127.0.0.1'  # Or "localhost"
        port = 5123

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.s:
                self.s.connect((host, port))
                while self.running:
                    data = self.s.recv(1024)
                    if not data:
                        break
                    if (data == b"<SERVER 5123> CLOSE PROGRAM"):
                        self.close()
                    self.data_queue.put(data.decode())
        except Exception as e:
            print("Server Error/Closed")
            self.close()

    def update_gui(self):
        try:
            data = self.data_queue.get_nowait()
            self.message_frame.configure(state='normal')
            if (self.selfMessage):
                self.message_frame.insert(tk.END, data + "\n", "self_message")
                self.selfMessage = False
            else:
                self.message_frame.insert(tk.END, data + "\n", "not_self_message")
            self.message_frame.configure(state='disabled')
            self.message_frame.see(tk.END)
        except queue.Empty:
            pass  # No data yet, ignore
        if self.running:
            self.master.after(100, self.update_gui) # Check every 100 ms

    def close(self):
        self.running = False
        self.master.destroy()

def main():
    root = tk.Tk()
    app = App(root)
    root.protocol("WM_DELETE_WINDOW", app.close)
    root.mainloop()

if __name__ == "__main__":
    main()
