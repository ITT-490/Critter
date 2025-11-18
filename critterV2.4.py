import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog # Added filedialog for save dialog
from datetime import datetime
import ipaddress
import time
# --- NEW PDF IMPORTS ---
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
# -----------------------

# --- Configuration ---
# List of ports to check sequentially on each host. If a host responds to ANY of these,
# it is marked as ACTIVE. This increases the chance of finding both Linux (22) and Windows (445) hosts.
PORTS_TO_CHECK = [22, 445]
SCAN_TIMEOUT = 0.25 # Faster timeout for speed
# ---------------------

# A global variable to store the final summary text (Active Hosts list) for the PDF function
# This list stores (ip_addr, hostname) tuples
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


# --------------------------------------
# Helper Funcion (Kept the same)
# --------------------------------------

def get_hostname(ip_addr):
    """
    Performs a reverse DNS lookup to find the hostname of an IP address.
    Returns the hostname if found, if not then it returns "Unkown Host" or the original IP.
    """

    try:
        # socket.gethostbyaddr returns a tuple: (hostname, aliaslist, ipaddrlist)
        hostname_info = socket.gethostbyaddr(ip_addr)
        return hostname_info[0]

    except socket.herror:
        # Error is raised if the hostname cannot be found via DNS
        return "Unkown Host"

    except Exception as e:
        # Handle other potential errors
        return f"Error: {e}"


# ----------------------------------------------------------------------
# Core Scanning Logic (Kept the same)
# ----------------------------------------------------------------------

def host_scan(target_ip, output_text_box, lock, active_hosts_list):
    """
    Checks if a host is active by attempting a quick TCP connect on the configured ports.
    Also performs a hostname lookup if active.
    """

    is_active = False
    hostname = "N/A"

    try:
        for port in PORTS_TO_CHECK:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(SCAN_TIMEOUT)

            # Attempt connection to the current port in the list
            result = s.connect_ex((target_ip, port))

            if result == 0:
                is_active = True
                s.close()
                hostname = get_hostname(target_ip)
                break # Stop checking other ports once one is found
            s.close()

    except (socket.gaierror, socket.error):
        pass

    finally:
        # Thread-safe writing to the GUI
        with lock:
            if is_active:
                active_hosts_list.append((target_ip, hostname))
                output_text_box.insert(tk.END, f"[ACTIVE] Host found: {target_ip} ({hostname})\n", 'active')
            else:
                output_text_box.insert(tk.END, f"[INACTIVE] Host not responding: {target_ip}\n", 'inactive')
            output_text_box.see(tk.END)


# ----------------------------------------------------------------------
# PDF Generation Function (NEW)
# ----------------------------------------------------------------------

def generate_pdf_report(active_hosts_data, scan_metadata):
    """
    Prompts the user for a save location and generates a PDF report using reportlab.
    """
    if not active_hosts_data:
        messagebox.showinfo("Report Error", "Cannot generate PDF: No hosts were found active in the last scan.")
        return

    # Use filedialog to ask user where to save the file
    filepath = filedialog.asksaveasfilename(
        defaultextension=".pdf",
        filetypes=[("PDF files", "*.pdf")],
        title="Save Scan Report as PDF",
        initialfile=f"Scan_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    )

    if not filepath:
        return # User canceled the save dialog

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

        for ip_addr, hostname_result in active_hosts_data:
            # Format the entry for the PDF
            entry = f"<b>IP Address:</b> {ip_addr} &nbsp;&nbsp;&nbsp; <b>Hostname:</b> {hostname_result}"
            story.append(Paragraph(entry, styles['Normal']))

        # Build the PDF
        doc.build(story)

        messagebox.showinfo("Success", f"PDF report successfully saved to:\n{filepath}")

    except Exception as e:
        messagebox.showerror("PDF Error", f"Failed to generate PDF report: {e}")


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

    # IMPORTANT: The global variables must be available to the button command
    global FINAL_ACTIVE_HOSTS_DATA, SCAN_METADATA

    # Create the main window
    window = tk.Tk()
    window.title("Critter IP Network Scanner")
    window.geometry("500x650")

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

        ip_targets = generate_ip_range(start_ip, end_ip)

        if not ip_targets:
            messagebox.showerror("Input Error", "Invalid IP range. Check start and end IP addresses.")
            return

        # Clear global list before new scan
        global FINAL_ACTIVE_HOSTS_DATA
        FINAL_ACTIVE_HOSTS_DATA = []

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

            # Store final results and metadata for the PDF function
            global FINAL_ACTIVE_HOSTS_DATA, SCAN_METADATA
            FINAL_ACTIVE_HOSTS_DATA = active_hosts
            SCAN_METADATA = {
                "Scan Duration": f"{duration} seconds",
                "Total IPs Scanned": len(ip_targets),
                "Active Hosts Found": len(active_hosts),
                "IP Range": f"{start_ip} to {end_ip}",
                "Ports Checked": ports_str
            }


            # Final summary message
            with gui_lock:
                output_text_box.insert(tk.END, "-" * 50 + "\n")
                output_text_box.insert(tk.END, "--- SCAN SUMMARY ---\n")
                for key, value in SCAN_METADATA.items():
                    output_text_box.insert(tk.END, f"{key}: {value}\n", 'active' if 'Active Hosts' in key else None)
                output_text_box.insert(tk.END, "Active Host List:\n")

                for ip_addr, hostname_result in active_hosts:
                    output_text_box.insert(tk.END, f"  - {ip_addr} ({hostname_result})\n", 'active')

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

    # --- NEW PDF BUTTON ---
    pdf_button = tk.Button(
        button_frame,
        text="💾 Save as PDF",
        command=lambda: generate_pdf_report(FINAL_ACTIVE_HOSTS_DATA, SCAN_METADATA),
        state=tk.DISABLED, # Disabled until the first scan is complete
        width=15
    )
    pdf_button.pack(side=tk.LEFT, padx=10)
    # ----------------------


    # Start the GUI event Loop
    window.mainloop()

if __name__ == "__main__":
    create_gui()
