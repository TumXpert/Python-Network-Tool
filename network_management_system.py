#!/usr/bin/env python3
"""
Full-Fledged Network Management System

Features:
- Network discovery using ARP (Scapy)
- Port scanning using Nmap (python-nmap)
- SNMP querying using Easysnmp
- Results stored in an SQLite database (SQLAlchemy)
- Periodic scanning (APScheduler)
- Web dashboard with device details and topology mapping (Flask, NetworkX, Matplotlib)

Usage:
    python network_management_system.py

Then open your browser to http://localhost:5000

DISCLAIMER: Only run this tool on networks you are authorized to scan.
"""

import json
import datetime
import threading
import time
import io

# --- Flask & Dashboard ---
from flask import Flask, render_template_string, request, redirect, url_for, send_file

# --- Scheduler ---
from apscheduler.schedulers.background import BackgroundScheduler

# --- Database (SQLAlchemy) ---
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker

# --- Networking Modules ---
from scapy.all import ARP, Ether, srp
import nmap

# Import Easysnmp for SNMP
import subprocess

import networkx as nx

# Set matplotlib backend to a non-interactive one (avoid GUI warnings)
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

#############################
# Database Setup (SQLite)
#############################

# Create an SQLite database file called network_devices.db
engine = create_engine('sqlite:///network_devices.db')
Base = declarative_base()

# Define a Device model to store discovered device info
class Device(Base):
    __tablename__ = 'devices'
    id = Column(Integer, primary_key=True)
    ip = Column(String, unique=True, nullable=False)
    mac = Column(String)
    last_seen = Column(DateTime)
    port_status = Column(Text)   # JSON string of port scan results
    snmp_data = Column(Text)     # JSON string of SNMP query results

Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
session = Session()

#############################
# Scanning Functions
#############################

def scan_network(ip_range):
    """
    Discover devices on the network using ARP requests.
    
    :param ip_range: Network in CIDR format (e.g., '192.168.88.0/24')
    :return: List of dictionaries with device IP and MAC
    """
    print(f"[+] Scanning network: {ip_range}")
    arp = ARP(pdst=ip_range)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    result = srp(packet, timeout=2, verbose=False)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})
    print(f"[DEBUG] {len(devices)} devices found on {ip_range}")
    return devices

def port_scan(ip, ports="22,80,443"):
    """
    Scan specified TCP ports on a device using Nmap.
    
    :param ip: Target IP address
    :param ports: Comma-separated list of ports (default "22,80,443")
    :return: Dictionary of port states
    """
    print(f"[+] Scanning ports on {ip}")
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, ports)
        port_status = {}
        if ip in nm.all_hosts() and 'tcp' in nm[ip]:
            for port in nm[ip]['tcp']:
                port_status[port] = nm[ip]['tcp'][port]['state']
        return port_status
    except Exception as e:
        print(f"[-] Error scanning {ip}: {e}")
        return {}

def get_snmp_data(ip, community='public', oid='1.3.6.1.2.1.1.1.0'):
    """
    Retrieve SNMP data using the snmpwalk command.
    
    :param ip: Device IP address
    :param community: SNMP community string
    :param oid: Object Identifier to query (default sysDescr)
    :return: Dictionary with SNMP results or error information
    """
    try:
        # Run the snmpwalk command as a subprocess
        command = ["snmpwalk", "-v", "2c", "-c", community, ip, oid]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        
        # The output of the snmpwalk command
        output = result.stdout.strip()

        # If snmpwalk fails (empty output), return an error
        if not output:
            return {"error": f"No data returned from SNMP query on {ip}"}

        # Parse the output to return in a dictionary format
        # (snmpwalk returns a single line in the format: OID = VALUE)
        result_dict = {}
        for line in output.splitlines():
            oid_value = line.split(" = ")
            if len(oid_value) == 2:
                result_dict[oid_value[0]] = oid_value[1]
        
        return result_dict

    except subprocess.CalledProcessError as e:
        return {"error": f"SNMP walk failed: {e}"}
    except Exception as e:
        return {"error": str(e)}
#############################
# Full Scan & Database Update
#############################

def run_full_scan(ip_range, ports="22,80,443", snmp_oid="1.3.6.1.2.1.1.1.0", snmp_community="public"):
    """
    Perform a full network scan:
      - Discover devices via ARP
      - Run port scanning on each device
      - Query SNMP data on each device
      - Update the database with results
    
    :param ip_range: Network range in CIDR format
    :param ports: Ports to scan (as comma-separated string)
    :param snmp_oid: SNMP OID to query
    :param snmp_community: SNMP community string
    """
    print("[+] Running full network scan...")
    discovered_devices = scan_network(ip_range)
    now = datetime.datetime.now()
    for dev in discovered_devices:
        ip = dev['ip']
        mac = dev['mac']
        # Get port scanning results
        ports_result = port_scan(ip, ports)
        # Get SNMP data using the new Easysnmp function
        snmp_result = get_snmp_data(ip, community=snmp_community, oid=snmp_oid)

        # Convert dictionaries to JSON strings for storage
        port_status_json = json.dumps(ports_result)
        snmp_data_json = json.dumps(snmp_result)

        # Update or add device in the database
        device = session.query(Device).filter_by(ip=ip).first()
        if device:
            device.mac = mac
            device.last_seen = now
            device.port_status = port_status_json
            device.snmp_data = snmp_data_json
        else:
            device = Device(ip=ip, mac=mac, last_seen=now,
                            port_status=port_status_json, snmp_data=snmp_data_json)
            session.add(device)
        session.commit()
    print("[+] Full scan complete.")

#############################
# Scheduler Setup (APScheduler)
#############################

# Default scan parameters (adjusted to your network)
ip_range_default = "192.168.88.0/24"  # Update this to your actual network range if needed
ports_default = "22,80,443"
snmp_oid_default = "1.3.6.1.2.1.1.1.0"
snmp_community_default = "public"

# Initialize the background scheduler to run the scan every 5 minutes
scheduler = BackgroundScheduler()
scheduler.add_job(
    lambda: run_full_scan(ip_range_default, ports_default, snmp_oid_default, snmp_community_default),
    'interval',
    minutes=5
)
scheduler.start()

#############################
# Flask Web Dashboard
#############################

app = Flask(__name__)

@app.route('/')
def index():
    """Dashboard: display a table of discovered devices and their scan results."""
    devices = session.query(Device).all()
    html = """
    <!doctype html>
    <html>
      <head>
        <title>Network Management Dashboard</title>
        <style>
          body { font-family: Arial, sans-serif; margin: 20px; }
          table { border-collapse: collapse; width: 100%; }
          th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
          th { background-color: #f2f2f2; }
          a { text-decoration: none; color: blue; }
        </style>
      </head>
      <body>
        <h1>Network Management Dashboard</h1>
        <p>
          <a href="{{ url_for('trigger_scan') }}">Run Manual Scan</a> |
          <a href="{{ url_for('topology') }}">View Topology Map</a>
        </p>
        <table>
          <tr>
            <th>ID</th>
            <th>IP</th>
            <th>MAC</th>
            <th>Last Seen</th>
            <th>Port Status</th>
            <th>SNMP Data</th>
          </tr>
          {% for device in devices %}
          <tr>
            <td>{{ device.id }}</td>
            <td>{{ device.ip }}</td>
            <td>{{ device.mac }}</td>
            <td>{{ device.last_seen }}</td>
            <td><pre>{{ device.port_status }}</pre></td>
            <td><pre>{{ device.snmp_data }}</pre></td>
          </tr>
          {% endfor %}
        </table>
      </body>
    </html>
    """
    return render_template_string(html, devices=devices)

@app.route('/scan')
def trigger_scan():
    """Manually trigger a full scan."""
    thread = threading.Thread(target=run_full_scan, args=(
        ip_range_default, ports_default, snmp_oid_default, snmp_community_default))
    thread.start()
    return redirect(url_for('index'))

@app.route('/topology')
def topology():
    """Generate and display the network topology graph."""
    devices = session.query(Device).all()
    graph = nx.Graph()

    for device in devices:
        ip = device.ip
        graph.add_node(ip)
        if device.snmp_data:
            snmp_data = json.loads(device.snmp_data)
            if '1.3.6.1.2.1.1.1.0' in snmp_data:
                graph.add_edge(ip, snmp_data['1.3.6.1.2.1.1.1.0'])
    
    # Plot the network graph
    plt.figure(figsize=(10, 10))
    nx.draw(graph, with_labels=True, node_size=500, node_color='skyblue', font_size=10)
    plt.title("Network Topology")
    
    # Save the figure to a BytesIO object
    img_io = io.BytesIO()
    plt.savefig(img_io, format='PNG')
    img_io.seek(0)
    plt.close()
    
    return send_file(img_io, mimetype='image/png')

#############################
# Start Flask App
#############################

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5000)
