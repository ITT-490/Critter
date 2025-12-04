import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
from datetime import datetime
import ipaddress
try:
    import psutil
    PSUTIL_AVAILABLE = True
except Exception:
    PSUTIL_AVAILABLE = False
import time
from concurrent.futures import ThreadPoolExecutor
# --- PDF IMPORTS ---
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
# -----------------------

# --- Configuration ---
# Default list of ports to check. This is now used as a default value.
DEFAULT_PORTS_TO_CHECK = [22, 445, 80] # Added port 80 as a common default
SCAN_TIMEOUT = 0.25 # Faster timeout for speed
# ---------------------

# A global variable to store the final summary text (Active Hosts list) for the PDF function
# This list now stores (ip_addr, hostname, open_port) tuples
FINAL_ACTIVE_HOSTS_DATA = []
SCAN_METADATA = {} # Stores scan duration, range, etc.

# ----------------------------------------------------------------------
# IP Range Generation Functions (Kept the same)
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


def discover_local_networks(max_hosts_warn=4096):
    """
    Attempts to discover the local IPv4 networks the host is connected to.

    Returns a list of ipaddress.IPv4Network objects.

    Behavior:
    - Prefer psutil.net_if_addrs() to obtain addresses and netmasks (cross-platform).
    - Fallback: open a UDP socket to a public IP to get the primary local IP and assume /24.
    - Filter out loopback and non-IPv4 addresses.
    """
    networks = []

    if PSUTIL_AVAILABLE:
        try:
            addrs = psutil.net_if_addrs()
            for ifname, addr_list in addrs.items():
                for addr in addr_list:
                    if addr.family == socket.AF_INET:
                        ip = addr.address
                        netmask = addr.netmask or '255.255.255.0'
                        try:
                            iface = ipaddress.IPv4Interface(f"{ip}/{netmask}")
                            net = iface.network
                            # skip loopback and very small/invalid networks
                            if not net.is_loopback:
                                networks.append(net)
                        except Exception:
                            # fallback to /24
                            try:
                                net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
                                if not net.is_loopback:
                                    networks.append(net)
                            except Exception:
                                continue
        except Exception:
            networks = []

    # Fallback if we couldn't use psutil or found nothing useful
    if not networks:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # doesn't actually send data
            s.connect(('8.8.8.8', 80))
            local_ip = s.getsockname()[0]
            s.close()
            net = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
            if not net.is_loopback:
                networks.append(net)
        except Exception:
            pass

    # Remove duplicates
    unique = []
    for n in networks:
        if all(n != u for u in unique):
            unique.append(n)

    # Optional: warn if networks are huge (too many hosts)
    final = []
    for net in unique:
        if net.num_addresses > max_hosts_warn:
            # keep it but user will be warned later before scanning
            final.append(net)
        else:
            final.append(net)

    return final


# --------------------------------------
# Helper Funcion (Kept the same)
# --------------------------------------

def get_hostname(ip_addr):
    """
    Performs a reverse DNS lookup to find the hostname of an IP address.
    Returns the hostname if found, if not then it returns "Unkown Host".
    """
    try:
        hostname_info = socket.gethostbyaddr(ip_addr)
        return hostname_info[0]
    except socket.herror:
        return "Unkown Host"
    except Exception as e:
        return f"Error: {e}"


# ----------------------------------------------------------------------
# Core Scanning Logic (UPDATED)
# ----------------------------------------------------------------------

# NOTE: The PORTS_TO_CHECK list is now passed as an argument.
def host_scan(target_ip, ports_list, output_text_box, lock, active_hosts_list):
    """
    Checks if a host is active by attempting a quick TCP connect on the configured ports.
    Records the first open port found and the hostname.
    """

    open_port = None
    hostname = "N/A"

    try:
        for port in ports_list: # Use the user-defined ports list
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(SCAN_TIMEOUT)

            # Attempt connection to the current port in the list
            result = s.connect_ex((target_ip, port))

            if result == 0:
                open_port = port
                s.close()
                hostname = get_hostname(target_ip)
                break # Stop checking other ports once one is found
            s.close()

    except (socket.gaierror, socket.error):
        pass

    finally:
        # Thread-safe writing to the GUI
        with lock:
            if open_port is not None:
                # Store (IP, hostname, port) tuple
                active_hosts_list.append((target_ip, hostname, open_port)) 
                output_text_box.insert(tk.END, f"[ACTIVE] Host found: {target_ip} ({hostname}) on Port: {open_port}\n", 'active')
            else:
                output_text_box.insert(tk.END, f"[INACTIVE] Host not responding: {target_ip}\n", 'inactive')
            output_text_box.see(tk.END)


# ----------------------------------------------------------------------
# PDF Generation Function (UPDATED for Port info)
# ----------------------------------------------------------------------

def generate_pdf_report(active_hosts_data, scan_metadata):
    """
    Prompts the user for a save location and generates a PDF report using reportlab.
    """
    if not active_hosts_data:
        messagebox.showinfo("Report Error", "Cannot generate PDF: No hosts were found active in the last scan.")
        return

    filepath = filedialog.asksaveasfilename(
        defaultextension=".pdf",
        filetypes=[("PDF files", "*.pdf")],
        title="Save Scan Report as PDF",
        initialfile=f"Scan_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    )

    if not filepath:
        return 

    try:
        # Setup the PDF document
        doc = SimpleDocTemplate(filepath, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        # --- Title ---
        title = f"Critter IP Network Scan Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        story.append(Paragraph(title, styles['Title']))
        story.append(Spacer(1, 12))

        # --- Metadata Summary ---
        story.append(Paragraph("<b>--- Scan Summary ---</b>", styles['Heading2']))
        story.append(Spacer(1, 6))

        for key, value in scan_metadata.items():
            story.append(Paragraph(f"<b>{key}:</b> {value}", styles['Normal']))

        story.append(Spacer(1, 12))

        # --- Active Hosts List ---
        story.append(Paragraph("<b>--- Active Hosts Found ({}) ---</b>".format(len(active_hosts_data)), styles['Heading2']))
        story.append(Spacer(1, 6))

        # ACTIVE HOSTS DATA NOW INCLUDES THE PORT
        for ip_addr, hostname_result, open_port in active_hosts_data: 
            # Format the entry for the PDF, now including the port
            entry = f"<b>IP Address:</b> {ip_addr} &nbsp;&nbsp;&nbsp; <b>Hostname:</b> {hostname_result} &nbsp;&nbsp;&nbsp; <b>Open Port:</b> {open_port}"
            story.append(Paragraph(entry, styles['Normal']))

        # Build the PDF
        doc.build(story)

        messagebox.showinfo("Success", f"PDF report successfully saved to:\n{filepath}")

    except Exception as e:
        messagebox.showerror("PDF Error", f"Failed to generate PDF report: {e}")


# ----------------------------------------------------------------------
# GUI Functions (UPDATED)
# ----------------------------------------------------------------------

def show_help_window():

    help_window = tk.Toplevel()
    help_window.title("Help")
    help_window.geometry("600x300")
    help_window.resizable(False, False)

    ports_str = ', '.join(map(str, DEFAULT_PORTS_TO_CHECK))
    help_text_content = f"""
    Python Network Host Scanner Help

    This tool is optimized for **network discovery** (finding active IPs) 
    by checking specific TCP ports.

    How to Use:
    1.) Enter the starting IP and ending IP address.
    2.) Enter the **Ports to Check** as a comma-separated list (e.g., 22,80,443,3389).
    3.) Click 'Start Scan' to begin checking all hosts.

    Method Note:
    The scanner performs a fast TCP check on the ports you specify. 
    If a host responds to ANY of these ports, it is marked as ACTIVE, 
    and the first port found is recorded.
        Default Ports: {ports_str}

        New Option:
        - Check "Scan local networks" to have Critter detect the network(s) your machine
            is attached to and scan those automatically. This uses psutil when available
            and falls back to a guessed /24 network if not. Be cautious: large networks
            can take a long time to scan.
    """

    help_text_box = scrolledtext.ScrolledText(help_window, width=50, height=10)
    help_text_box.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
    help_text_box.insert(tk.END, help_text_content)
    help_text_box.config(state=tk.DISABLED)


def create_gui():

    # IMPORTANT: The global variables must be available to the button command
    global FINAL_ACTIVE_HOSTS_DATA, SCAN_METADATA

    # Create the main window
    window = tk.Tk()
    window.title("Critter IP Network Scanner")
    window.geometry("500x700") # Made slightly taller for the new input

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

    start_ip_label = tk.Label(ip_frame, text="Start IP:")
    start_ip_label.pack(side=tk.LEFT, padx=5)
    start_ip_entry = tk.Entry(ip_frame, width=15)
    start_ip_entry.insert(0, "192.168.150.1")
    start_ip_entry.pack(side=tk.LEFT)

    end_ip_label = tk.Label(ip_frame, text="End IP:")
    end_ip_label.pack(side=tk.LEFT, padx=5)
    end_ip_entry = tk.Entry(ip_frame, width=15)
    end_ip_entry.insert(0, "192.168.150.50")
    end_ip_entry.pack(side=tk.LEFT)

    # --- Scan local networks checkbox ---
    local_scan_var = tk.BooleanVar(value=False)
    def toggle_range_entries(*args):
        if local_scan_var.get():
            start_ip_entry.config(state=tk.DISABLED)
            end_ip_entry.config(state=tk.DISABLED)
        else:
            start_ip_entry.config(state=tk.NORMAL)
            end_ip_entry.config(state=tk.NORMAL)

    local_scan_check = tk.Checkbutton(window, text="Scan local networks (auto-detect)", variable=local_scan_var, command=toggle_range_entries)
    local_scan_check.pack(pady=5)

    # --- NEW PORT INPUT WIDGET ---
    ports_frame = tk.Frame(window)
    ports_frame.pack(pady=5)
    
    ports_label = tk.Label(ports_frame, text="Ports (e.g., 22,80,443):")
    ports_label.pack(side=tk.LEFT, padx=5)
    
    ports_entry = tk.Entry(ports_frame, width=40)
    ports_entry.insert(0, ','.join(map(str, DEFAULT_PORTS_TO_CHECK))) 
    ports_entry.pack(side=tk.LEFT)
    # -----------------------------


    # Output the display area
    output_text_box = scrolledtext.ScrolledText(window, width=50, height=25)
    output_text_box.pack(pady=10, padx=10)

    # Configure tags for color-coding the output
    output_text_box.tag_config('active', foreground='green')
    output_text_box.tag_config('inactive', foreground='gray')

    # Create a lock for thread-safe GUI updates
    gui_lock = threading.Lock()


    # Scan button logic
    def start_scan_thread():

        start_ip = start_ip_entry.get()
        end_ip = end_ip_entry.get()
        
        # Parse the ports from the new input field
        ports_input = ports_entry.get().replace(' ', '')
        try:
            ports_to_check = [int(p) for p in ports_input.split(',') if p.isdigit() and 0 < int(p) <= 65535]
            if not ports_to_check:
                 messagebox.showerror("Input Error", "Please enter valid, comma-separated ports (1-65535).")
                 return
        except ValueError:
            messagebox.showerror("Input Error", "Invalid port format. Use comma-separated numbers (e.g., 22,80).")
            return


        # If user selected automatic local network discovery, use that instead
        if local_scan_var.get():
            networks = discover_local_networks()
            if not networks:
                messagebox.showerror("Discovery Error", "Could not discover local networks. Please verify your network interfaces or uncheck the auto-scan option.")
                return

            # Build list of target IPs from discovered networks (host addresses only)
            ip_targets = []
            total_addrs = 0
            for net in networks:
                total_addrs += net.num_addresses
                if net.num_addresses > 4096:
                    proceed = messagebox.askyesno("Large Network Warning", f"Discovered network {net} contains {net.num_addresses} addresses and may take a long time to scan. Continue?")
                    if not proceed:
                        return
                # use .hosts() to exclude network/broadcast addresses
                for ip in net.hosts():
                    ip_targets.append(str(ip))

            if not ip_targets:
                messagebox.showerror("Discovery Error", "No usable host addresses found in discovered networks.")
                return
            ip_range_description = ", ".join(str(n) for n in networks)
        else:
            ip_targets = generate_ip_range(start_ip, end_ip)

            if not ip_targets:
                messagebox.showerror("Input Error", "Invalid IP range. Check start and end IP addresses.")
                return
            ip_range_description = f"{start_ip} to {end_ip}"

        # Clear global list before new scan
        global FINAL_ACTIVE_HOSTS_DATA
        FINAL_ACTIVE_HOSTS_DATA = []

        # Clear output box and print header
        output_text_box.delete('1.0', tk.END)
        start_time = time.time()
        ports_str = ', '.join(map(str, ports_to_check))

        output_text_box.insert(tk.END, "-" * 50 + "\n")
        output_text_box.insert(tk.END, f"Scanning IP range: {start_ip} to {end_ip}\n")
        output_text_box.insert(tk.END, f"Checking reachability on **USER-DEFINED** ports: {ports_str}\n")
        output_text_box.insert(tk.END, "Scanning started at: " + str(datetime.now()) + "\n")
        output_text_box.insert(tk.END, "-" * 50 + "\n")


        active_hosts = [] # List to store confirmed active IPs (ip, hostname, port)

        def master_scan_process():
            """The master thread process that launches and monitors host-scan tasks using a thread pool."""
            # Limit concurrency to avoid creating thousands of threads
            max_workers = 200
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [executor.submit(host_scan, ip, ports_to_check, output_text_box, gui_lock, active_hosts) for ip in ip_targets]
                # Wait for all futures to complete and propagate exceptions if any
                for f in futures:
                    try:
                        f.result()
                    except Exception:
                        # Individual host_scan errors are already handled; ignore here
                        pass

            end_time = time.time()
            duration = round(end_time - start_time, 2)

            # Store final results and metadata for the PDF function
            global FINAL_ACTIVE_HOSTS_DATA, SCAN_METADATA
            FINAL_ACTIVE_HOSTS_DATA = active_hosts
            SCAN_METADATA = {
                "Scan Duration": f"{duration} seconds",
                "Total IPs Scanned": len(ip_targets),
                "Active Hosts Found": len(active_hosts),
                "IP Range": ip_range_description,
                "Ports Checked": ports_str
            }


            # Final summary message
            with gui_lock:
                output_text_box.insert(tk.END, "-" * 50 + "\n")
                output_text_box.insert(tk.END, "--- SCAN SUMMARY ---\n")
                for key, value in SCAN_METADATA.items():
                    output_text_box.insert(tk.END, f"{key}: {value}\n", 'active' if 'Active Hosts' in key else None)
                output_text_box.insert(tk.END, "Active Host List:\n")

                # Print results, now including the port
                for ip_addr, hostname_result, open_port in active_hosts:
                    output_text_box.insert(tk.END, f"  - {ip_addr} ({hostname_result}) [Port: {open_port}]\n", 'active')

                output_text_box.insert(tk.END, "-" * 50 + "\n")
                output_text_box.see(tk.END)
                # Enable the PDF button after the scan is complete
                pdf_button.config(state=tk.NORMAL)


        # Start the master thread to prevent the GUI from freezing
        master_thread = threading.Thread(target=master_scan_process)
        master_thread.start()
        # Disable the PDF button during the scan
        pdf_button.config(state=tk.DISABLED)


    # Frame for buttons
    button_frame = tk.Frame(window)
    button_frame.pack(pady=10)

    scan_button = tk.Button(button_frame, text="Start Scan", command=start_scan_thread, width=15)
    scan_button.pack(side=tk.LEFT, padx=10)

    # --- PDF BUTTON ---
    pdf_button = tk.Button(
        button_frame,
        text="💾 Save as PDF",
        # Lambda function now passes the updated list format
        command=lambda: generate_pdf_report(FINAL_ACTIVE_HOSTS_DATA, SCAN_METADATA), 
        state=tk.DISABLED,
        width=15
    )
    pdf_button.pack(side=tk.LEFT, padx=10)
    # ----------------------


    # Start the GUI event Loop
    window.mainloop()

if __name__ == "__main__":
    create_gui()

