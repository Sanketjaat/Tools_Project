#!/usr/bin/env python3
import argparse
import logging
import sqlite3
from datetime import datetime
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import json
import os

# Configuration
LOG_DB = "firewall_logs.db"
RULES_FILE = "firewall_rules.json"
DEFAULT_RULES = {
    "rules": [
        {"type": "block", "ip": "10.0.0.1", "port": "22", "protocol": "tcp", "reason": "Block SSH"},
        {"type": "allow", "ip": "8.8.8.8", "protocol": "udp", "port": "53", "reason": "Allow Google DNS"}
    ]
}

class Firewall:
    def __init__(self, interface="eth0", gui=False):
        self.interface = interface
        self.rules = self.load_rules()
        self.running = False
        self.packet_count = {"allowed": 0, "blocked": 0}
        self.setup_logging()
        
        if gui:
            self.start_gui()
        else:
            self.start_cli()

    def setup_logging(self):
        """Initialize SQLite logging database"""
        conn = sqlite3.connect(LOG_DB)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                source_ip TEXT,
                dest_ip TEXT,
                source_port INTEGER,
                dest_port INTEGER,
                protocol TEXT,
                action TEXT,
                rule_reason TEXT
            )
        """)
        conn.close()

    def load_rules(self):
        """Load rules from JSON file or create default"""
        if os.path.exists(RULES_FILE):
            with open(RULES_FILE, 'r') as f:
                return json.load(f)["rules"]
        else:
            with open(RULES_FILE, 'w') as f:
                json.dump(DEFAULT_RULES, f, indent=4)
            return DEFAULT_RULES["rules"]

    def log_packet(self, packet, action, reason):
        """Log packet to database"""
        try:
            conn = sqlite3.connect(LOG_DB)
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                protocol = packet.sprintf("%IP.proto%")
                
                src_port = dst_port = None
                if TCP in packet:
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                elif UDP in packet:
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport
                
                conn.execute(
                    "INSERT INTO logs (timestamp, source_ip, dest_ip, source_port, dest_port, protocol, action, rule_reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (timestamp, src_ip, dst_ip, src_port, dst_port, protocol, action, reason)
                )
                conn.commit()
        except Exception as e:
            logging.error(f"Logging error: {e}")
        finally:
            conn.close()

    def process_packet(self, packet):
        """Apply firewall rules to each packet"""
        if not IP in packet:
            return
            
        action = "allow"  # Default action
        
        for rule in self.rules:
            try:
                # Check IP match
                ip_match = ("ip" not in rule) or (packet[IP].src == rule["ip"]) or (packet[IP].dst == rule["ip"])
                
                # Check protocol match
                proto_match = ("protocol" not in rule) or (
                    rule["protocol"].lower() == packet.sprintf("%IP.proto%").lower()
                )
                
                # Check port match
                port_match = True
                if "port" in rule:
                    if TCP in packet:
                        port_match = packet[TCP].dport == int(rule["port"]) or packet[TCP].sport == int(rule["port"])
                    elif UDP in packet:
                        port_match = packet[UDP].dport == int(rule["port"]) or packet[UDP].sport == int(rule["port"])
                    else:
                        port_match = False
                
                if ip_match and proto_match and port_match:
                    action = rule["type"]
                    reason = rule.get("reason", "No reason provided")
                    break
                    
            except Exception as e:
                logging.error(f"Rule processing error: {e}")
                continue
        
        # Update counters and log
        self.packet_count[action + "ed"] += 1
        self.log_packet(packet, action, reason)
        
        if action == "block":
            if TCP in packet:
                send(RST(packet), verbose=0)
            return f"Blocked packet from {packet[IP].src}"
        return None

    def start_sniffing(self):
        """Start packet capture loop"""
        self.running = True
        logging.info(f"Starting firewall on interface {self.interface}")
        
        try:
            sniff(
                iface=self.interface,
                prn=self.process_packet,
                stop_filter=lambda _: not self.running,
                store=0
            )
        except Exception as e:
            logging.error(f"Sniffing error: {e}")
            self.running = False

    def start_cli(self):
        """Command-line interface"""
        print(f"Firewall started on {self.interface} (Press Ctrl+C to stop)")
        print(f"Loaded {len(self.rules)} rules from {RULES_FILE}")
        
        try:
            self.start_sniffing()
        except KeyboardInterrupt:
            self.running = False
            print("\nFirewall stopped")
            print(f"Summary: {self.packet_count['allowed']} allowed, {self.packet_count['blocked']} blocked")

    def start_gui(self):
        """Graphical user interface"""
        self.root = tk.Tk()
        self.root.title("Python Firewall")
        
        # Main frame
        frame = ttk.Frame(self.root, padding="10")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Interface selection
        ttk.Label(frame, text="Interface:").grid(row=0, column=0)
        self.iface_var = tk.StringVar(value=self.interface)
        ttk.Entry(frame, textvariable=self.iface_var).grid(row=0, column=1)
        
        # Stats display
        ttk.Label(frame, text="Allowed:").grid(row=1, column=0)
        self.allowed_var = tk.StringVar(value="0")
        ttk.Label(frame, textvariable=self.allowed_var).grid(row=1, column=1)
        
        ttk.Label(frame, text="Blocked:").grid(row=2, column=0)
        self.blocked_var = tk.StringVar(value="0")
        ttk.Label(frame, textvariable=self.blocked_var).grid(row=2, column=1)
        
        # Control buttons
        self.start_btn = ttk.Button(frame, text="Start", command=self.start_firewall)
        self.start_btn.grid(row=3, column=0)
        
        ttk.Button(frame, text="Stop", command=self.stop_firewall).grid(row=3, column=1)
        ttk.Button(frame, text="View Logs", command=self.view_logs).grid(row=4, columnspan=2)
        
        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(frame, textvariable=self.status_var).grid(row=5, columnspan=2)
        
        # Start GUI loop
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.mainloop()

    def start_firewall(self):
        """Start firewall from GUI"""
        self.interface = self.iface_var.get()
        self.start_btn.config(state=tk.DISABLED)
        self.status_var.set("Running...")
        
        # Start sniffing in background thread
        threading.Thread(target=self.start_sniffing, daemon=True).start()
        
        # Start stats update loop
        self.update_stats()

    def stop_firewall(self):
        """Stop firewall from GUI"""
        self.running = False
        self.start_btn.config(state=tk.NORMAL)
        self.status_var.set("Stopped")

    def update_stats(self):
        """Update GUI counters"""
        if self.running:
            self.allowed_var.set(str(self.packet_count["allowed"]))
            self.blocked_var.set(str(self.packet_count["blocked"]))
            self.root.after(1000, self.update_stats)

    def view_logs(self):
        """Show log viewer window"""
        log_win = tk.Toplevel(self.root)
        log_win.title("Firewall Logs")
        
        # Create treeview
        columns = ("timestamp", "source_ip", "dest_ip", "protocol", "action", "reason")
        tree = ttk.Treeview(log_win, columns=columns, show="headings")
        
        for col in columns:
            tree.heading(col, text=col.capitalize())
            tree.column(col, width=100)
        
        tree.pack(fill=tk.BOTH, expand=True)
        
        # Load logs
        try:
            conn = sqlite3.connect(LOG_DB)
            cursor = conn.execute("SELECT timestamp, source_ip, dest_ip, protocol, action, rule_reason FROM logs ORDER BY id DESC LIMIT 100")
            
            for row in cursor:
                tree.insert("", tk.END, values=row)
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load logs: {e}")
        finally:
            conn.close()

    def on_close(self):
        """Handle window close"""
        self.running = False
        self.root.destroy()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Python Personal Firewall")
    parser.add_argument("-i", "--interface", default="eth0", help="Network interface to monitor")
    parser.add_argument("-g", "--gui", action="store_true", help="Enable graphical interface")
    args = parser.parse_args()
    
    firewall = Firewall(interface=args.interface, gui=args.gui)
