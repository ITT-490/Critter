import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox
from datetime import datetime
import ipaddress 
import time

# --- Configuration ---
# List of ports to check sequentially on each host. If a host responds to ANY of these,
# it is marked as ACTIVE. This increases the chance of finding both Linux (22) and Windows (445) hosts.
PORTS_TO_CHECK = [22, 445] 
SCAN_TIMEOUT = 0.25 # Faster timeout for speed
# ---------------------

# ----------------------------------------------------------------------
# IP Range Generation Functions
# ----------------------------------------------------------------------

def ip_to_int(ip_addr):
    """Converts an IP address string to an integer."""
    try:
        return int(ipaddress.IPv4Address(ip_addr))
    except ipaddress.AddressValueError:
        return None

def int_to_ip(ip_int):
    """Converts an integer back to an IP address string."""
    return str(ipaddress.IPv4Address(ip_int))

def generate_ip_range(start_ip, end_ip):
    """Generates a list of all IP addresses between the start and end IP (inclusive)."""
    start_int = ip_to_int(start_ip)
    end_int = ip_to_int(end_ip)

    if start_int is None or end_int is None or start_int > end_int:
        return []
        
    ip_list = []
    for ip_int in range(start_int, end_int + 1):
        ip_list.append(int_to_ip(ip_int))
    return ip_list

# ----------------------------------------------------------------------
# Core Scanning Logic (Modified for Multi-Port Check)
# ----------------------------------------------------------------------

def host_scan(target_ip, output_text_box, lock, active_hosts_list):
    """
    Checks if a host is active by attempting a quick TCP connect on the configured ports.
    """
    
    is_active = False
    
    try:
        for port in PORTS_TO_CHECK:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(SCAN_TIMEOUT) 

            # Attempt connection to the current port in the list
            result = s.connect_ex((target_ip, port)) 

            if result == 0:
                is_active = True
                s.close()
                break # Stop checking other ports once one is found
            s.close()
            
    except (socket.gaierror, socket.error):
        pass 
        
    finally:
        # Thread-safe writing to the GUI
        with lock:
            if is_active:
                active_hosts_list.append(target_ip)
                output_text_box.insert(tk.END, f"[ACTIVE] Host found: {target_ip}\n", 'active')
            else:
                output_text_box.insert(tk.END, f"[INACTIVE] Host not responding: {target_ip}\n", 'inactive')
            output_text_box.see(tk.END)

# ----------------------------------------------------------------------
# GUI Functions
# ----------------------------------------------------------------------

def show_help_window():
    
    help_window = tk.Toplevel()
    help_window.title("Help")
    help_window.geometry("600x270")
    help_window.resizable(False, False)

    # Updated help text to mention multi-port check
    ports_str = ', '.join(map(str, PORTS_TO_CHECK))
    help_text_content = f"""
    Python Network Host Scanner Help

    This tool is optimized for **network discovery** (finding active IPs) 
    in a given IP range. It does NOT perform a full port scan.

    How to Use:
    1.) Enter the starting IP address (e.g., 192.168.150.1).
    2.) Enter the ending IP address (e.g., 192.168.150.50).
    3.) Click 'Start Scan' to begin checking all hosts in the range.

    Method Note:
    The scanner performs a fast TCP check on the following ports to determine host activity: {ports_str}.
    If a host responds to ANY of these ports, it is marked as ACTIVE.
    """

    help_text_box = scrolledtext.ScrolledText(help_window, width=50, height=10)
    help_text_box.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
    help_text_box.insert(tk.END, help_text_content)
    help_text_box.config(state=tk.DISABLED) 


def create_gui():
    
    # Create the main window
    window = tk.Tk()
    window.title("Critter IP Network Scanner")
    window.geometry("500x600")
    
    # ... (Icon and Menubar setup)
    try:
        icon = tk.PhotoImage(file="Critter_IoT_Logo.png")
        window.iconphoto(False, icon)
    except tk.TclError:
        print("Warning: Could not load icon file 'Critter_IoT_Logo.png'.")

    menubar = tk.Menu(window)
    window.config(menu=menubar)

    help_menu = tk.Menu(menubar, tearoff=0)
    menubar.add_cascade(label="Help", menu=help_menu)
    help_menu.add_command(label="About", command=show_help_window)

    
    # Create and place IP Range widgets
    
    ip_frame = tk.Frame(window)
    ip_frame.pack(pady=10)
    
    start_ip_label = tk.Label(ip_frame, text="Start IP Address:")
    start_ip_label.pack(side=tk.LEFT, padx=5)
    start_ip_entry = tk.Entry(ip_frame, width=15)
    start_ip_entry.insert(0, "192.168.150.1") 
    start_ip_entry.pack(side=tk.LEFT)
    
    end_ip_label = tk.Label(ip_frame, text="End IP Address:")
    end_ip_label.pack(side=tk.LEFT, padx=5)
    end_ip_entry = tk.Entry(ip_frame, width=15)
    end_ip_entry.insert(0, "192.168.150.50") 
    end_ip_entry.pack(side=tk.LEFT)


    # Output the display area
    output_text_box = scrolledtext.ScrolledText(window, width=50, height=25)
    output_text_box.pack(pady=10)
    
    # Configure tags for color-coding the output
    output_text_box.tag_config('active', foreground='green')
    output_text_box.tag_config('inactive', foreground='gray')
    
    # Create a lock for thread-safe GUI updates
    gui_lock = threading.Lock()


    # Scan button logic
    def start_scan_thread():
        
        start_ip = start_ip_entry.get()
        end_ip = end_ip_entry.get()
            
        ip_targets = generate_ip_range(start_ip, end_ip)
        
        if not ip_targets:
            messagebox.showerror("Input Error", "Invalid IP range. Check start and end IP addresses.")
            return

        # Clear output box and print header
        output_text_box.delete('1.0', tk.END) 
        start_time = time.time()
        ports_str = ', '.join(map(str, PORTS_TO_CHECK))

        output_text_box.insert(tk.END, "-" * 50 + "\n")
        output_text_box.insert(tk.END, f"Scanning IP range: {start_ip} to {end_ip}\n")
        output_text_box.insert(tk.END, f"Checking reachability on ports: {ports_str}\n")
        output_text_box.insert(tk.END, "Scanning started at: " + str(datetime.now()) + "\n")
        output_text_box.insert(tk.END, "-" * 50 + "\n")
        
        
        active_hosts = [] # List to store confirmed active IPs
        
        def master_scan_process():
            """The master thread process that launches and monitors all host scan threads."""
            threads = []
            
            for ip in ip_targets:
                # Start a separate thread for EACH IP in the range
                thread = threading.Thread(target=host_scan, 
                                          args=(ip, output_text_box, gui_lock, active_hosts))
                threads.append(thread)
                thread.start()
                
            # Wait for all individual host-scan threads to complete
            for thread in threads:
                thread.join()
            
            end_time = time.time()
            duration = round(end_time - start_time, 2)
                
            # Final summary message
            with gui_lock:
                output_text_box.insert(tk.END, "-" * 50 + "\n")
                output_text_box.insert(tk.END, "--- SCAN SUMMARY ---\n")
                output_text_box.insert(tk.END, f"Scan Duration: {duration} seconds\n")
                output_text_box.insert(tk.END, f"Total IPs Scanned: {len(ip_targets)}\n")
                output_text_box.insert(tk.END, f"Active Hosts Found: {len(active_hosts)}\n", 'active')
                output_text_box.insert(tk.END, "Active Host List:\n")
                for host in active_hosts:
                    output_text_box.insert(tk.END, f"  - {host}\n", 'active')
                output_text_box.insert(tk.END, "-" * 50 + "\n")
                output_text_box.see(tk.END)


        # Start the master thread to prevent the GUI from freezing
        master_thread = threading.Thread(target=master_scan_process)
        master_thread.start()
        

    scan_button = tk.Button(window, text="Start Scan", command=start_scan_thread)
    scan_button.pack(pady=10)


    # Start the GUI event Loop
    window.mainloop()

if __name__ == "__main__":
    create_gui()