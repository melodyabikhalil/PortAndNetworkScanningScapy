from tkinter import *
import ipaddress
import socket
from tkinter import ttk


import sys
sys.path.insert(1, '../Ports')
sys.path.insert(1, '../Network')

from syn import syn_scan
from connect import connect_scan
from fin import fin_scan
from null import null_scan
from ack import ack_scan
from udp import udp_scan
from window import window_scan
from xmas import xmas_scan
from custom_flags import custom_flags_scan


from network import network_scan
from icmp_network import remote_network_scan
 
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
    global scan_flags #give scan_flags as paremeter for the custom_scan function
    scan_flags = ""
    #print(host_address.get())
    #print(scan_mode.get())
    #print(host_address.get())
    try:
        address = ipaddress.ip_address(host_address.get())
        host = host_address.get()
        dport = dst_port.get()
        sport = src_port.get()
        response_text.delete("1.0", "end")
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
        elif(scan_mode.get() == 8):
            print("Custom Scan")
            if(ack_flag.get() == 1):
                scan_flags = scan_flags + "A"
            if(fin_flag.get() == 1):
                scan_flags = scan_flags + "F"
            if(urg_flag.get() == 1):
                scan_flags = scan_flags + "U"
            if(psh_flag.get() == 1):
                scan_flags = scan_flags + "P"
            if(rst_flag.get() == 1):
                scan_flags = scan_flags + "R"
            if(ece_flag.get() == 1):
                scan_flags = scan_flags + "E"
            if(cwr_flag.get() == 1):
                scan_flags = scan_flags + "C"
            if(ns_flag.get() == 1):
                scan_flags = scan_flags + "N"
            response_text.insert(END,custom_flags_scan(host,dport,sport,scan_flags))
            print(scan_flags)
    except Exception as ex:
        template = "An exception of type {0} occurred. Arguments:\n{1!r}"
        message = template.format(type(ex).__name__, ex.args)
        print (message)


#network scanning tab
        
def net_scan():
    try:
        address = host_network_address.get()
        #apres avoir recu le response
        if(net_scan_mode.get() == 0):
            print("ARP scan")
            response_data = network_scan(address)
        elif(net_scan_mode.get() == 1):
            print("ICMP scan")
            response_data = network_scan(address)
        response_entry.insert(END,"IP\t\tMAC\n")
        for elt in response_data:
            response_entry.insert(END,elt['ip'] + "\t\t" + elt['mac'] + "\n")
            #Label(frame,text = "ip "+ elt['ip'] + " " + "mac " + elt['mac'])
            print( "ip "+ elt['ip'] + " " + "mac " + elt['mac'])
    except Exception as ex:
        template = "An exception of type {0} occurred. Arguments:\n{1!r}"
        message = template.format(type(ex).__name__, ex.args)
        print (message)

        
def reset():
    host_address.delete(0, 'end')
    scan_mode.set(0)
    dst_port.delete(0, 'end')
    src_port.delete(0, 'end')
    response_text.delete("1.0", "end")
    
def reset_net():
    host_network_address.delete(0,'end')
    net_scan_mode.set(0)
    response_entry.delete("1.0", "end")
    
def toggle():
    if scan_mode.get() == 8:
        custom_frame.grid()
    else:
        custom_frame.grid_remove()
        
def toggle_other():
    custom_frame.grid_remove()
    ack_flag.set(0)
    fin_flag.set(0)

    
#Ports Scanning GUI Setup
    
host_label = Label(port_tab, text = 'Host', font='Helvetica 10 bold').grid(column = 0, row = 0, sticky = W, padx = 15, pady=10)
host_address = Entry(port_tab)
host_address.grid(column = 0, row = 1, padx = 20)
mode_label = Label(port_tab, text = 'Mode', font='Helvetica 10 bold').grid(column = 0, row = 2, sticky = W, pady = 2,padx = 15)
scan_mode = IntVar()
scan_mode.set(0)
tcp_syn_scan_rb = Radiobutton(port_tab, text = "TCP SYN Scan", variable = scan_mode, value = 0,command = toggle_other).grid(row = 3, column = 0, sticky = W,padx = 20)
tcp_connect_scan_rb = Radiobutton(port_tab, text = "TCP Connect Scan", variable = scan_mode, value = 1,command = toggle_other).grid(row = 3, column = 1, sticky = W)
tcp_null_scan_rb = Radiobutton(port_tab, text = "TCP NULL Scan", variable = scan_mode, value = 2,command = toggle_other).grid(row = 4, column = 0, sticky = W,padx = 20)
fin_scan_rb = Radiobutton(port_tab, text = "TCP FIN Scan", variable = scan_mode, value = 3,command = toggle_other).grid(row = 4, column = 1, sticky = W)
xmas_scan_rb = Radiobutton(port_tab, text = "TCP Xmas Scan", variable = scan_mode, value = 4,command = toggle_other).grid(row = 5, column = 0, sticky = W,padx = 20)
tcp_ack_scan_rb = Radiobutton(port_tab, text = "TCP ACK Scan", variable = scan_mode, value = 5,command = toggle_other).grid(row = 5, column = 1, sticky = W)
tcp_window_scan_rb = Radiobutton(port_tab, text = "TCP Window Scan", variable = scan_mode, value = 6,command = toggle_other).grid(row = 6, column = 0, sticky = W,padx = 20)
udp_scan_rb = Radiobutton(port_tab, text = "UDP Scan", variable = scan_mode, value = 7,command = toggle_other).grid(row = 6, column = 1, sticky = W)
custom_scan_rb = Radiobutton(port_tab, text = "Custom Scan", variable = scan_mode, value = 8, command = toggle).grid(row = 3, column = 3, sticky = W)
custom_frame = Frame(port_tab)
custom_frame.grid(row = 4, column = 3, sticky = W)
ack_flag = IntVar()
fin_flag = IntVar()
urg_flag = IntVar()
psh_flag = IntVar()
rst_flag = IntVar()
ece_flag = IntVar()
cwr_flag = IntVar()
ns_flag = IntVar()
Checkbutton(custom_frame, text = "ACK", variable = ack_flag).grid(row = 0, column = 0)
Checkbutton(custom_frame, text = "FIN", variable = fin_flag).grid(row = 1, column = 0)
Checkbutton(custom_frame, text = "URG ", variable = urg_flag).grid(row = 2, column = 0)
Checkbutton(custom_frame, text = "PSH", variable = psh_flag).grid(row = 0, column = 1)
Checkbutton(custom_frame, text = "RST", variable = rst_flag).grid(row = 2, column = 1)
Checkbutton(custom_frame, text = "ECE", variable = ece_flag).grid(row = 1, column = 1)
Checkbutton(custom_frame, text = "CWR", variable = cwr_flag).grid(row = 0, column = 2)
Checkbutton(custom_frame, text = "NS", variable = ns_flag).grid(row = 1, column = 2)
custom_frame.grid_remove()
scan_options_label = Label(port_tab, text = 'Scan Options', font='Helvetica 10 bold').grid(column = 0, row = 7, sticky = W, pady = 2, padx = 15)
dst_port_label = Label(port_tab, text = 'Destination Port').grid(column = 0, row = 8, sticky = W,pady = 1, padx = 20)
dst_port = Entry(port_tab)
dst_port.grid(column = 1, row = 8,pady = 1) 
src_port_label = Label(port_tab, text = 'Source Port').grid(column = 0, row = 9, sticky = W,pady = 1, padx = 20)
src_port = Entry(port_tab)
src_port.grid(column = 1, row = 9,pady = 1)

scan_button = Button(port_tab, text = 'Scan', command = scan).grid(column = 0, row = 10, sticky = W, pady = 5, padx = 20)
reset_button = Button(port_tab,text = 'Reset', command = reset).grid(column = 1, row = 10, sticky = W, pady = 5)
response_text = Text(port_tab, width = 40, height=10)
response_text.grid(column = 0, columnspan = 2, sticky = W, padx = 20)


#Network Scanning GUI Setup
        
host_network_label = Label(net_tab, text = 'Host', font='Helvetica 10 bold').grid(column = 0, row = 0, sticky = W, padx = 15, pady=10)
host_network_address = Entry(net_tab)
host_network_address.grid(column = 0, row = 1, sticky = W, padx = 20)
net_scan_mode = IntVar()
net_scan_mode.set(0)
arp_scan_rb = Radiobutton(net_tab, text = "ARP Scan", variable = net_scan_mode, value = 0).grid(row = 2, column = 0, sticky = W, padx = 20)
arp_scan_rb = Radiobutton(net_tab, text = "ICMP Scan", variable = net_scan_mode, value = 1).grid(row = 3, column = 0, sticky = W, padx = 20)
scan_button_net = Button(net_tab, text = 'Scan', command = net_scan).grid(column = 0, row = 4,sticky = W, padx = 20)
reset_button_net = Button(net_tab, text = 'Reset', command = reset_net).grid(column = 0, row = 4)
response_entry = Text(net_tab, width = 50)
response_entry.grid(column = 0, row = 6,sticky = W,  padx = 20)
scrollb = Scrollbar(net_tab, command = response_entry.yview)
response_entry['yscrollcommand'] = scrollb.set





tab_control.pack(expand=1, fill='both')
window.geometry("550x550")
window.mainloop()
