from tkinter import *
import ipaddress
import socket
from tkinter import ttk


import sys
sys.path.insert(1, '../Ports')

from syn import syn_scan
from connect import connect_scan
from fin import fin_scan
from null import null_scan
from ack import ack_scan
from udp import udp_scan
from window import window_scan
from xmas import xmas_scan
 
window = Tk()
 
window.title("Network & Port Scanning")
 
tab_control = ttk.Notebook(window)
 
port_tab = ttk.Frame(tab_control)
 
net_tab = ttk.Frame(tab_control)
 
tab_control.add(port_tab, text='Port Scanning')
 
tab_control.add(net_tab, text='Network Scanning')
 

#port scanning tab

def scan():
    global address
    #print(host_address.get())
    #print(scan_mode.get())
    #print(host_address.get())
    try:
        address = ipaddress.ip_address(host_address.get())
        host = host_address.get()
        dport = dst_port.get()
        sport = src_port.get()
        if(scan_mode.get() == 0):
            print('SYN')
            response_text.insert(END,syn_scan(host,dport,sport))
        elif(scan_mode.get() == 1):
            print('Connect')
            response_text.insert(END,connect_scan(host,dport,sport))
        elif(scan_mode.get() == 2):
            print("TCP NULL Scan")
            response_text.insert(END,null_scan(host,dport,sport))
        elif(scan_mode.get() == 3):
            print("FIN Scan")
            response_text.insert(END,fin_scan(host,dport,sport))
        elif(scan_mode.get() == 4):
            print("Xmas Scan")
            response_text.insert(END,xmas_scan(host,dport,sport))
        elif(scan_mode.get() == 5):
            print("TCP ACK Scan")
            response_text.insert(END,ack_scan(host,dport,sport))
        elif(scan_mode.get() == 6):
            print("TCP Window Scan")
            response_text.insert(END,window_scan(host,dport,sport))
        elif(scan_mode.get() == 7):
            print("UDP Scan")
            response_text.insert(END,udp_scan(host,dport,sport))
    except Exception as ex:
        template = "An exception of type {0} occurred. Arguments:\n{1!r}"
        message = template.format(type(ex).__name__, ex.args)
        print (message)
def reset():
    host_address.delete(0, 'end')
    scan_mode.set(0)
    dst_port.delete(0, 'end')
    src_port.delete(0, 'end')
    response_text.set("")

host_label = Label(port_tab, text = 'Host').grid(column = 0, row = 0, sticky = W)
host_address = Entry(port_tab)
host_address.grid(column = 0, row = 1, sticky = W)
mode_label = Label(port_tab, text = 'Mode').grid(column = 0, row = 2, sticky = W, pady = 2)
scan_mode = IntVar()
scan_mode.set(0)
tcp_syn_scan_rb = Radiobutton(port_tab, text = "TCP SYN Scan", variable = scan_mode, value = 0).grid(row = 3, column = 0, sticky = W)
tcp_connect_scan_rb = Radiobutton(port_tab, text = "TCP Connect Scan", variable = scan_mode, value = 1).grid(row = 3, column = 1, sticky = W)
tcp_null_scan_rb = Radiobutton(port_tab, text = "TCP NULL Scan", variable = scan_mode, value = 2).grid(row = 4, column = 0, sticky = W)
fin_scan_rb = Radiobutton(port_tab, text = "TCP FIN Scan", variable = scan_mode, value = 3).grid(row = 4, column = 1, sticky = W)
xmas_scan_rb = Radiobutton(port_tab, text = "TCP Xmas Scan", variable = scan_mode, value = 4).grid(row = 5, column = 0, sticky = W)
tcp_ack_scan_rb = Radiobutton(port_tab, text = "TCP ACK Scan", variable = scan_mode, value = 5).grid(row = 5, column = 1, sticky = W)
tcp_window_scan_rb = Radiobutton(port_tab, text = "TCP Window Scan", variable = scan_mode, value = 6).grid(row = 6, column = 0, sticky = W)
udp_scan_rb = Radiobutton(port_tab, text = "UDP Scan", variable = scan_mode, value = 7).grid(row = 6, column = 1, sticky = W)

scan_options_label = Label(port_tab, text = 'Scan Options').grid(column = 0, row = 7, sticky = W, pady = 2)
dst_port_label = Label(port_tab, text = 'Destination Port').grid(column = 0, row = 8, sticky = W,pady = 1)
dst_port = Entry(port_tab)
dst_port.grid(column = 1, row = 8,pady = 1) 
src_port_label = Label(port_tab, text = 'Source Port').grid(column = 0, row = 9, sticky = W,pady = 1)
src_port = Entry(port_tab)
src_port.grid(column = 1, row = 9,pady = 1)

scan_button = Button(port_tab, text = 'Scan', command = scan).grid(column = 0, row = 10, sticky = W, pady = 2)
reset_button = Button(port_tab,text = 'Reset', command = reset).grid(column = 1, row = 10, sticky = W, pady = 2)
response_text = Text(port_tab, width = 35)
response_text.grid(column = 0, row = 11,sticky = W, columnspan = 2)
#network scanning tab
def net_scan():
    try:
        address = ipaddress.ip_address(host_network_address.get())
        #apres avoir recu le response
        response_dummy_data = [{'ip':'172.12.12.13','mac':'rfsfsg'},{'ip':'172.12.12.13','mac':'rfsfsg'},{'ip':'172.12.12.13','mac':'rfsfsg'}]
        for elt in response_dummy_data:
            response_entry.insert(END,"ip "+ elt['ip'] + " " + "mac " + elt['mac'] + "\n")
            #Label(frame,text = "ip "+ elt['ip'] + " " + "mac " + elt['mac'])
            print( "ip "+ elt['ip'] + " " + "mac " + elt['mac'])
    except:
        print('invalid host address')
host_network_label = Label(net_tab, text = 'Host').grid(column = 0, row = 0, sticky = W)
host_network_address = Entry(net_tab)
host_network_address.grid(column = 0, row = 1, sticky = W)
scan_button_net = Button(net_tab, text = 'Scan', command = net_scan).grid(column = 0, row = 1)

response_entry = Text(net_tab, width = 50)
response_entry.grid(column = 0, row = 2,sticky = W)
scrollb = Scrollbar(net_tab, command = response_entry.yview)
response_entry['yscrollcommand'] = scrollb.set





tab_control.pack(expand=1, fill='both')
window.geometry("300x450")
window.mainloop()
