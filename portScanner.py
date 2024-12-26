import socket
import threading
from queue import Queue
from tkinter import *
from tkinter import messagebox, filedialog, ttk
from tkinter.ttk import Progressbar
from datetime import datetime

# Variables for stopping the scan
stop_scan = False
open_ports = []

def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def portscanner(port, target):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((target, port))
        return True
    except:
        return False
    finally:
        sock.close()

def threadWorker(target, queue, result_text, progress_var, total_ports):
    global stop_scan, open_ports
    while not queue.empty() and not stop_scan:
        port = queue.get()
        if portscanner(port, target):
            open_ports.append(port)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            result_text.insert(END, f"[{timestamp}] Port {port} is open!\n")
        progress = (1 - queue.qsize() / total_ports) * 100  # Calculate progress
        root.after(0, progress_var.set, progress)  # Update progress in the main thread
        queue.task_done()

def start_scan_threaded():
    global stop_scan
    stop_scan = False
    threading.Thread(target=start_scan, daemon=True).start()

def start_scan():
    global stop_scan, open_ports
    target = ip_entry.get()
    if not is_valid_ip(target):
        messagebox.showerror("Invalid IP", "Please enter a valid IPv4 address.")
        return

    result_text.delete(1.0, END)
    open_ports = []
    queue = Queue()
    total_ports = 1000

    for port in range(1, total_ports + 1):
        queue.put(port)

    threadList = []
    progress_var.set(0)

    for _ in range(20):
        thread = threading.Thread(
            target=threadWorker,
            args=(target, queue, result_text, progress_var, total_ports)
        )
        threadList.append(thread)
        thread.start()

    for thread in threadList:
        thread.join()

    if not stop_scan:
        result_text.insert(END, f"\nScan complete! Open ports: {open_ports}\n")
        messagebox.showinfo("Scan Complete", "Port scanning has finished.")

def stop_scan_threaded():
    global stop_scan
    stop_scan = True
    messagebox.showinfo("Scan Stopped", "Port scanning has been stopped.")

def save_results():
    file_path = filedialog.asksaveasfilename(defaultextension=".txt",
                                             filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
    if file_path:
        with open(file_path, "w") as file:
            file.write(result_text.get(1.0, END))
        messagebox.showinfo("Saved", "Scan results saved successfully.")

# UI setup
root = Tk()
root.title("Port Scanner")
root.geometry("800x600")

# Dark Mode Colors
root.configure(bg="#1e1e2f")  # Dark background color

# Header Section
header_frame = Frame(root, bg="#2e2e3b")  # Dark header
header_frame.pack(fill=X, pady=10)
header_label = Label(header_frame, text="Port Scanner Tool", font=("Arial", 18, "bold"), fg="white", bg="#2e2e3b")
header_label.pack()

# IP Entry Section
frame = Frame(root, bg="#1e1e2f")
frame.pack(pady=20)

ip_label = Label(frame, text="Target IP Address:", font=("Arial", 12), bg="#1e1e2f", fg="white")
ip_label.grid(row=0, column=0, padx=10, pady=5, sticky=W)

ip_entry = Entry(frame, font=("Arial", 12), width=30)
ip_entry.grid(row=0, column=1, padx=10, pady=5)

# Buttons Section
button_frame = Frame(root, bg="#1e1e2f")
button_frame.pack(pady=10)

scan_button = Button(button_frame, text="Start Scan", font=("Arial", 12), command=start_scan_threaded, bg="#4CAF50", fg="white", width=12)
scan_button.grid(row=0, column=0, padx=5)

stop_button = Button(button_frame, text="Stop Scan", font=("Arial", 12), command=stop_scan_threaded, bg="#f44336", fg="white", width=12)
stop_button.grid(row=0, column=1, padx=5)

save_button = Button(button_frame, text="Save Results", font=("Arial", 12), command=save_results, bg="#03A9F4", fg="white", width=12)
save_button.grid(row=0, column=2, padx=5)

# Progress Bar
style = ttk.Style()
style.theme_use("default")

# Modify the default progress bar style for dark mode
style.configure("Horizontal.TProgressbar", background="#4CAF50", troughcolor="#2e2e3b", thickness=10)

progress_var = DoubleVar()
progress_bar = Progressbar(root, variable=progress_var, length=600, mode="determinate", style="Horizontal.TProgressbar")
progress_bar.pack(pady=10)

# Results Section
result_text = Text(root, font=("Courier", 12), height=15, wrap=WORD, bg="#2e2e3b", fg="white", borderwidth=2, relief="solid")
result_text.pack(padx=20, pady=10, fill=BOTH, expand=True)

# Footer
footer_label = Label(root, text="Developed by [Noor Asghar, Shahneela Iqbal]", font=("Arial", 10), fg="#888888", bg="#1e1e2f")
footer_label.pack(pady=5)

root.mainloop()
