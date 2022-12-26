


import json
import requests
import pandas as pd
import time
import urllib3
from calendar import timegm, monthrange
from datetime import datetime, timedelta
import math
import numpy as np
import collections




from os.path import join






device_inventory_labels = ['device_name','vendor','model','os','version','hw_revision','role','ip_address']
interface_inventory_labels = ['link_id','unique_id','device_name','interface_name','interface_type','interface_ip_address','peer_device_name','peer_interface','peer_interface_ip_address','transceiver_vendor','interface_role']
metric_policy_labels = ['metric','entity','pattern_type','P1','P1P','P2','P2P','P3','P3P']
incident_policy_labels = ['incident_name','period','entity_table','entity_column','entity_name','impact_type','impact_details']
event_template_labels = ['event_id','event_name','event_type','scope','fields','field_map','message','severity']
event_policy_labels = ['policy_name','event_id','period','probability','entity_table','entity_column','entity_name','fields']

device_metric_list = ['mem_utilization','cpu_utilization','bng_subscribers']
interface_metric_list = ['traffic_out_mbps','traffic_in_mbps']




def generate_device_inventory():
    device_inventory_df = pd.DataFrame(columns = device_inventory_labels )
    #generate core devices
    for i in range(1,5):
        if i in range(1,4):
            inventory_entry = {
                'device_name': 'C-'+str(i),
                'vendor': 'Juniper',
                'model': 'PTX10000',
                'os': 'Junos',
                'version':'21.3R1',
                'hw_revision': 'hw3959392',
                'role':'core',
                'ip_address':'10.2.1.'+str(i)
            }
            
        else:
            inventory_entry = {
                'device_name': 'C-4',
                'vendor': 'Juniper',
                'model': 'PTX10000',
                'os': 'Junos',
                'version':'22.1R3',
                'hw_revision': 'hw3959392',
                'role':'core',
                'ip_address':'10.2.1.4'
            }
        device_inventory_df=device_inventory_df.append(inventory_entry,ignore_index=True)
    
    #generate PE devices
    for i in range(1,101):
        if i in range(1,51):
            inventory_entry = {
                'device_name': 'PE-'+str(i),
                'vendor': 'Juniper',
                'model': 'MX960',
                'os': 'Junos',
                'version':'21.3R1',
                'hw_revision': 'hw3958888',
                'role':'PE',
                'ip_address':'10.2.2.'+str(i)
            }
        elif i in range(51,55):
            inventory_entry = {
                'device_name': 'PE-'+str(i),
                'vendor': 'Juniper',
                'model': 'MX960',
                'os': 'Junos',
                'version':'22.1R3',
                'hw_revision': 'hw3958888',
                'role':'PE',
                'ip_address':'10.2.2.'+str(i)
            }
        elif i in range(55,59):
            inventory_entry = {
                'device_name': 'PE-'+str(i),
                'vendor': 'Juniper',
                'model': 'MX960',
                'os': 'Junos',
                'version':'22.1R3',
                'hw_revision': 'hw3958890',
                'role':'PE',
                'ip_address':'10.2.2.'+str(i)
            }
        elif i in range(59,61):
            inventory_entry = {
                'device_name': 'PE-'+str(i),
                'vendor': 'Juniper',
                'model': 'MX960',
                'os': 'Junos',
                'version':'21.3R1',
                'hw_revision': 'hw3958890',
                'role':'PE',
                'ip_address':'10.2.2.'+str(i)
            }
        elif i in range(61,91):
            inventory_entry = {
                'device_name': 'PE-'+str(i),
                'vendor': 'Cisco',
                'model': 'ASR9K',
                'os': 'IOS-XR',
                'version':'7.5',
                'hw_revision': 'hw-asr-950777',
                'role':'PE',
                'ip_address':'10.2.2.'+str(i)
            }
        elif i in range(91,98):
            inventory_entry = {
                'device_name': 'PE-'+str(i),
                'vendor': 'Cisco',
                'model': 'ASR9K',
                'os': 'IOS-XR',
                'version':'7.6',
                'hw_revision': 'hw-asr-950777',
                'role':'PE',
                'ip_address':'10.2.2.'+str(i)
            }
        elif i in range(98,101):
            inventory_entry = {
                'device_name': 'PE-'+str(i),
                'vendor': 'Cisco',
                'model': 'ASR9K',
                'os': 'IOS-XR',
                'version':'7.5',
                'hw_revision': 'hw-asr-950778',
                'role':'PE',
                'ip_address':'10.2.2.'+str(i)
            }
            
        device_inventory_df=device_inventory_df.append(inventory_entry,ignore_index=True)
    
    #generate sd-wan edge devices
    
    for i in range(1,101):
        if i == 1 :
            for j in range(1,3):
                inventory_entry = {
                    'device_name': 'E-'+str(i)+'-'+str(j),
                    'vendor': 'Versa',
                    'model': 'versa_1',
                    'os': 'VOS',
                    'version':'21.1.0',
                    'hw_revision': 'hw-versa-0001',
                    'role':'vedge_hub',
                    'ip_address':'10.3.'+str(i)+'.'+str(j)
                }
                device_inventory_df=device_inventory_df.append(inventory_entry,ignore_index=True)
        elif i in range(2,96):
            for j in range(1,3):
                inventory_entry = {
                    'device_name': 'E-'+str(i)+'-'+str(j),
                    'vendor': 'Versa',
                    'model': 'versa_1',
                    'os': 'VOS',
                    'version':'21.1.0',
                    'hw_revision': 'hw-versa-0001',
                    'role':'vedge_branch',
                    'ip_address':'10.3.'+str(i)+'.'+str(j)
                }
                device_inventory_df=device_inventory_df.append(inventory_entry,ignore_index=True)
        elif i in range(96,100):
            for j in range(1,3):
                inventory_entry = {
                    'device_name': 'E-'+str(i)+'-'+str(j),
                    'vendor': 'Versa',
                    'model': 'versa_2',
                    'os': 'VOS',
                    'version':'21.1.1',
                    'hw_revision': 'hw-versa-0001',
                    'role':'vedge_branch',
                    'ip_address':'10.3.'+str(i)+'.'+str(j)
                }
                device_inventory_df=device_inventory_df.append(inventory_entry,ignore_index=True)
        elif i == 100:
            for j in range(1,3):
                inventory_entry = {
                    'device_name': 'E-'+str(i)+'-'+str(j),
                    'vendor': 'Versa',
                    'model': 'versa_2',
                    'os': 'VOS',
                    'version':'21.1.0',
                    'hw_revision': 'hw-versa-0002',
                    'role':'vedge_hub',
                    'ip_address':'10.3.'+str(i)+'.'+str(j)
                }
                device_inventory_df=device_inventory_df.append(inventory_entry,ignore_index=True)
    
    
    return device_inventory_df




def random_allocate(item_list):
    num_items = len(item_list)
    random_number = np.random.randint(0,100)
    prev = 0
    for i in range(num_items):
        if random_number >= prev and random_number<(item_list[i][1]+prev):
            value = item_list[i][0]
        else:
            prev += item_list[i][1]
    return value
    


def generate_interface_inventory():
    interface_inventory_df = pd.DataFrame(columns = interface_inventory_labels )
    #'link_id','device_name','interface_name','interface_type','interface_ip_address','peer_device_name','peer_interface','peer_interface_ip','transceiver_vendor',
    #core devices
    for x in range(1,5):
        for y in range(1,101):
            inventory_entry = {
                'link_id':'11.'+str(x)+'.'+str(y),
                'device_name': 'C-'+str(x),
                'interface_name': 'et-1-1-'+str(y),
                'interface_type': '400G',
                'interface_ip_address': '11.'+str(x)+'.'+str(y)+'.1/30',
                'peer_device_name': 'PE-'+str(y),
                'peer_interface': 'et-1-1-'+str(x),
                'peer_interface_ip_address': '11.'+str(x)+'.'+str(y)+'.2/30',
                'transceiver_vendor': 'Acacia' if y<30 else ('APIC' if y>=30 and y<80 else 'Applied'),
                'interface_role':'core'
            }
            interface_inventory_df=interface_inventory_df.append(inventory_entry,ignore_index=True)
    #PE devices
    for y in range(1,101):
        for x in range(1,5):
            inventory_entry = {
                'link_id':'11.'+str(x)+'.'+str(y),
                'device_name': 'PE-'+str(y),
                'interface_name': 'et-1-1-'+str(x),
                'interface_type': '400G',
                'interface_ip_address': '11.'+str(x)+'.'+str(y)+'.2/30',
                'peer_device_name': 'C-'+str(x),
                'peer_interface': 'et-1-1-'+str(y),
                'peer_interface_ip_address': '11.'+str(x)+'.'+str(y)+'.1/30',
                'transceiver_vendor': 'Acacia' if y<30 else ('APIC' if y>=30 and y<80 else 'Applied'),
                'interface_role':'core'
            }
            interface_inventory_df=interface_inventory_df.append(inventory_entry,ignore_index=True)
        for z in range(1,3):
            inventory_entry = {
                'link_id':'12.'+str(y)+'.'+str(z),
                'device_name': 'PE-'+str(y),
                'interface_name': 'et-1-2-'+str(z),
                'interface_type': '10G',
                'interface_ip_address': '12.'+str(y)+'.'+str(z)+'.1/30',
                'peer_device_name': 'E-'+str(y)+'-'+str(z),
                'peer_interface': 'et-1-1-1',
                'peer_interface_ip_address': '12.'+str(y)+'.'+str(z)+'.2/30',
                'transceiver_vendor': 'Acacia' if y<30 else ('APIC' if y>=30 and y<80 else 'Applied'),
                'interface_role':'edge'
            }
            interface_inventory_df=interface_inventory_df.append(inventory_entry,ignore_index=True)
    
    
    #sd-wan edge devices
    for y in range(1,101):
        for z in range(1,3):
            inventory_entry = {
                'link_id':'12.'+str(y)+'.'+str(z),
                'device_name': 'E-'+str(y)+'-'+str(z),
                'interface_name': 'et-1-1-1',
                'interface_type': '10G',
                'interface_ip_address': '12.'+str(y)+'.'+str(z)+'.2/30',
                'peer_device_name': 'PE-'+str(y),
                'peer_interface': 'et-1-2-'+str(z),
                'peer_interface_ip_address': '12.'+str(y)+'.'+str(z)+'.1/30',
                'transceiver_vendor': 'Acacia' if y<30 else ('APIC' if y>=30 and y<80 else 'Applied'),
                'interface_role':'edge'
            }
            interface_inventory_df=interface_inventory_df.append(inventory_entry,ignore_index=True)
            if y in [1,100]:
                for a in range(2,100):
                    for b in range(1,3):
                         #these are the tunnels starting on the sd-wan hubs towards the branches   
                            inventory_entry = {
                                'link_id':'tun-'+str(y)+'-'+str(z)+'-'+str(a)+'-'+str(b),
                                'device_name': 'E-'+str(y)+'-'+str(z),
                                'interface_name': 'tun-'+str(a)+'-'+str(b),
                                'interface_type': 'tunnel',
                                'interface_ip_address': str(y)+'.'+str(z)+'.'+str(a)+'.'+str(b)+'1/30',
                                'peer_device_name': 'E-'+str(a)+'-'+str(b),
                                'peer_interface': 'tun-'+str(y)+'-'+str(z),
                                'peer_interface_ip_address': str(y)+'.'+str(z)+'.'+str(a)+'.'+str(b)+'2/30',
                                'transceiver_vendor': 'n/a',
                                'interface_role':'sd-wan'
                            }
                            interface_inventory_df=interface_inventory_df.append(inventory_entry,ignore_index=True)
            else:
                for a in [1,100]:
                    for b in range(1,3):
                            inventory_entry = {
                                'link_id':'tun-'+str(a)+'-'+str(b)+'-'+str(y)+'-'+str(z),
                                'device_name': 'E-'+str(y)+'-'+str(z),
                                'interface_name': 'tun-'+str(a)+'-'+str(b),
                                'interface_type': 'tunnel',
                                'interface_ip_address': str(y)+'.'+str(z)+'.'+str(a)+'.'+str(b)+'2/30',
                                'peer_device_name': 'E-'+str(a)+'-'+str(b),
                                'peer_interface': 'tun-'+str(y)+'-'+str(z),
                                'peer_interface_ip_address': str(y)+'.'+str(z)+'.'+str(a)+'.'+str(b)+'1/30',
                                'transceiver_vendor': 'n/a',
                                'interface_role':'sd-wan'
                            }
                            interface_inventory_df=interface_inventory_df.append(inventory_entry,ignore_index=True)
    interface_inventory_df['unique_id']=interface_inventory_df['device_name']+'-'+interface_inventory_df['interface_name']
    return interface_inventory_df




def generate_device_metric_policy(device_inventory_df):
    device_metric_policy_df = pd.DataFrame(columns=metric_policy_labels)
    for metric in device_metric_list:
        if metric == 'mem_utilization':
            for i,entity in device_inventory_df.iterrows():
                if entity['device_name'].split('-')[0]=='C':
                    if int(entity['device_name'].split('-')[1]) in range(1,4):
                        
                        
                        policy_entry = {
                            'metric': metric,
                            'entity': entity['device_name'],
                            'pattern_type': 'stationary',
                            'P1': [30,35],
                            'P1P': 100,
                            'P2':[0,1],
                            'P2P':0,
                            'P3':[0,1],
                            'P3P':0  
                        }
                    elif int(entity['device_name'].split('-')[1]) in range(4,5):
                                                
                        policy_entry = {
                            'metric': metric,
                            'entity': entity['device_name'],
                            'pattern_type': 'trending',
                            'P1': [30,95,'day'],
                            'P1P': 100,
                            'P2':[0,1],
                            'P2P':0,
                            'P3':[0,1],
                            'P3P':0  
                        }
                elif entity['device_name'].split('-')[0]=='PE':
                    if int(entity['device_name'].split('-')[1]) in range(1,51):                        
                        policy_entry = {
                            'metric': metric,
                            'entity': entity['device_name'],
                            'pattern_type': 'stationary',
                            'P1': [20,25],
                            'P1P': 100,
                            'P2':[0,1],
                            'P2P':0,
                            'P3':[0,1],
                            'P3P':0  
                        }
                    elif int(entity['device_name'].split('-')[1]) in range(51,59):                        
                        policy_entry = {
                            'metric': metric,
                            'entity': entity['device_name'],
                            'pattern_type': 'stationary',
                            'P1': [20,25],
                            'P1P': 80,
                            'P2':[70,75],
                            'P2P':15,
                            'P3':[90,100],
                            'P3P':5  
                        }
                    elif int(entity['device_name'].split('-')[1]) in range(59,61):                        
                        policy_entry = {
                            'metric': metric,
                            'entity': entity['device_name'],
                            'pattern_type': 'stationary',
                            'P1': [75,80],
                            'P1P': 100,
                            'P2':[0,1],
                            'P2P':0,
                            'P3':[0,1],
                            'P3P':0  
                        }
                    elif int(entity['device_name'].split('-')[1]) in range(61,90):                        
                        policy_entry = {
                            'metric': metric,
                            'entity': entity['device_name'],
                            'pattern_type': 'stationary',
                            'P1': [40,45],
                            'P1P': 100,
                            'P2':[0,1],
                            'P2P':0,
                            'P3':[0,1],
                            'P3P':0  
                        }
                    elif int(entity['device_name'].split('-')[1]) in range(91,98):                        
                        policy_entry = {
                            'metric': metric,
                            'entity': entity['device_name'],
                            'pattern_type': 'stationary',
                            'P1': [40,45],
                            'P1P': 80,
                            'P2':[90,95],
                            'P2P':20,
                            'P3':[0,1],
                            'P3P':0  
                        }
                    elif int(entity['device_name'].split('-')[1]) in range(98,101):                        
                        policy_entry = {
                            'metric': metric,
                            'entity': entity['device_name'],
                            'pattern_type': 'stationary',
                            'P1': [30,35],
                            'P1P': 70,
                            'P2':[50,55],
                            'P2P':30,
                            'P3':[0,1],
                            'P3P':0  
                        }
                elif entity['device_name'].split('-')[0]=='E':
                    if int(entity['device_name'].split('-')[1]) in range(1,100):                        
                        policy_entry = {
                            'metric': metric,
                            'entity': entity['device_name'],
                            'pattern_type': 'stationary',
                            'P1': [30,35],
                            'P1P': 100,
                            'P2':[50,55],
                            'P2P':0,
                            'P3':[0,1],
                            'P3P':0  
                        }
                    elif int(entity['device_name'].split('-')[1]) in range(100,101):                        
                        policy_entry = {
                            'metric': metric,
                            'entity': entity['device_name'],
                            'pattern_type': 'stationary',
                            'P1': [75,80],
                            'P1P': 100,
                            'P2':[0,1],
                            'P2P':0,
                            'P3':[0,1],
                            'P3P':0  
                        }        
                device_metric_policy_df=device_metric_policy_df.append(policy_entry,ignore_index=True)
        elif metric == 'cpu_utilization':
            for i,entity in device_inventory_df.iterrows():
                if entity['device_name'].split('-')[0]=='C':
                    if int(entity['device_name'].split('-')[1]) in range(1,4):
                                                
                        policy_entry = {
                            'metric': metric,
                            'entity': entity['device_name'],
                            'pattern_type': 'stationary',
                            'P1': [30,35],
                            'P1P': 100,
                            'P2':[0,1],
                            'P2P':0,
                            'P3':[0,1],
                            'P3P':0  
                        }
                    elif int(entity['device_name'].split('-')[1]) in range(4,5):
                                                
                        policy_entry = {
                            'metric': metric,
                            'entity': entity['device_name'],
                            'pattern_type': 'stationary',
                            'P1': [70,75],
                            'P1P': 100,
                            'P2':[0,1],
                            'P2P':0,
                            'P3':[0,1],
                            'P3P':0  
                        }
                elif entity['device_name'].split('-')[0]=='PE':
                    if int(entity['device_name'].split('-')[1]) in range(1,51):                        
                        policy_entry = {
                            'metric': metric,
                            'entity': entity['device_name'],
                            'pattern_type': 'stationary',
                            'P1': [20,25],
                            'P1P': 100,
                            'P2':[0,1],
                            'P2P':0,
                            'P3':[0,1],
                            'P3P':0  
                        }
                    elif int(entity['device_name'].split('-')[1]) in range(51,59):                        
                        policy_entry = {
                            'metric': metric,
                            'entity': entity['device_name'],
                            'pattern_type': 'stationary',
                            'P1': [20,25],
                            'P1P': 80,
                            'P2':[70,75],
                            'P2P':15,
                            'P3':[90,100],
                            'P3P':5  
                        }
                    elif int(entity['device_name'].split('-')[1]) in range(59,61):                        
                        policy_entry = {
                            'metric': metric,
                            'entity': entity['device_name'],
                            'pattern_type': 'stationary',
                            'P1': [75,80],
                            'P1P': 100,
                            'P2':[0,1],
                            'P2P':0,
                            'P3':[0,1],
                            'P3P':0  
                        }
                    elif int(entity['device_name'].split('-')[1]) in range(61,90):                        
                        policy_entry = {
                            'metric': metric,
                            'entity': entity['device_name'],
                            'pattern_type': 'stationary',
                            'P1': [40,45],
                            'P1P': 100,
                            'P2':[0,1],
                            'P2P':0,
                            'P3':[0,1],
                            'P3P':0  
                        }
                    elif int(entity['device_name'].split('-')[1]) in range(91,98):                        
                        policy_entry = {
                            'metric': metric,
                            'entity': entity['device_name'],
                            'pattern_type': 'stationary',
                            'P1': [40,45],
                            'P1P': 80,
                            'P2':[90,95],
                            'P2P':20,
                            'P3':[0,1],
                            'P3P':0  
                        }
                    elif int(entity['device_name'].split('-')[1]) in range(98,101):                        
                        policy_entry = {
                            'metric': metric,
                            'entity': entity['device_name'],
                            'pattern_type': 'stationary',
                            'P1': [80,85],
                            'P1P': 100,
                            'P2':[0,1],
                            'P2P':0,
                            'P3':[0,1],
                            'P3P':0  
                        }
                elif entity['device_name'].split('-')[0]=='E':
                    if int(entity['device_name'].split('-')[1]) in range(1,30):                        
                        policy_entry = {
                            'metric': metric,
                            'entity': entity['device_name'],
                            'pattern_type': 'stationary',
                            'P1': [30,35],
                            'P1P': 100,
                            'P2':[50,55],
                            'P2P':0,
                            'P3':[0,1],
                            'P3P':0  
                        }
                    elif int(entity['device_name'].split('-')[1]) in range(30,60):                        
                        policy_entry = {
                            'metric': metric,
                            'entity': entity['device_name'],
                            'pattern_type': 'stationary',
                            'P1': [50,55],
                            'P1P':100,
                            'P2':[70,75],
                            'P2P':0,
                            'P3':[95,100],
                            'P3P':0  
                        } 
                    elif int(entity['device_name'].split('-')[1]) in range(60,98):                        
                        policy_entry = {
                            'metric': metric,
                            'entity': entity['device_name'],
                            'pattern_type': 'stationary',
                            'P1': [80,82],
                            'P1P':100,
                            'P2':[70,75],
                            'P2P':0,
                            'P3':[95,100],
                            'P3P':0  
                        }
                    elif int(entity['device_name'].split('-')[1]) in range(98,100):                        
                        policy_entry = {
                            'metric': metric,
                            'entity': entity['device_name'],
                            'pattern_type': 'stationary',
                            'P1': [10,12],
                            'P1P':100,
                            'P2':[70,75],
                            'P2P':0,
                            'P3':[95,100],
                            'P3P':0  
                        }    
                    elif int(entity['device_name'].split('-')[1]) in range(100,101):                        
                        policy_entry = {
                            'metric': metric,
                            'entity': entity['device_name'],
                            'pattern_type': 'stationary',
                            'P1': [30,35],
                            'P1P':100,
                            'P2':[70,75],
                            'P2P':0,
                            'P3':[95,100],
                            'P3P':10  
                        }        
                device_metric_policy_df=device_metric_policy_df.append(policy_entry,ignore_index=True)
        elif metric == 'bng_subscribers':
            for i,entity in device_inventory_df.iterrows():
                if entity['device_name'].split('-')[0]=='PE':
                    if int(entity['device_name'].split('-')[1]) in range(1,5):
                                                
                        policy_entry = {
                            'metric': metric,
                            'entity': entity['device_name'],
                            'pattern_type': 'seasonal',
                            'P1': [20000,21000],
                            'P1P': 96,
                            'P2':[25000,26000],
                            'P2P':2,
                            'P3':[5000,6000],
                            'P3P':2  
                        }
                        device_metric_policy_df=device_metric_policy_df.append(policy_entry,ignore_index=True)
                    elif int(entity['device_name'].split('-')[1]) in range(5,101):
                                                
                        policy_entry = {
                            'metric': metric,
                            'entity': entity['device_name'],
                            'pattern_type': 'trending',
                            'P1': [5000,5100,'month','seasonal',2000],
                            'P1P': 96,
                            'P2':[500,550],
                            'P2P':4,
                            'P3':[0,1],
                            'P3P':0  
                        }
                        device_metric_policy_df=device_metric_policy_df.append(policy_entry,ignore_index=True)
                else:                       
                    policy_entry = {
                            'metric': metric,
                            'entity': entity['device_name'],
                            'pattern_type': 'stationary',
                            'P1': [0,1],
                            'P1P': 100,
                            'P2':[0,1],
                            'P2P':0,
                            'P3':[0,1],
                            'P3P':0  
                    }
                    device_metric_policy_df=device_metric_policy_df.append(policy_entry,ignore_index=True)
    return device_metric_policy_df




def generate_link_metric_policy(interface_inventory_df):
    link_metric_policy_df = pd.DataFrame(columns=metric_policy_labels)
   
    for i,entity in interface_inventory_df.iterrows():

        if entity['device_name'].split('-')[0]=='C':
            if int(entity['interface_name'].split('-')[3]) in range(1,91):
                #this is the traffic out entry
                policy_entry = {
                    'metric': 'traffic_out_mbps',
                    'entity': entity['unique_id'],
                    'pattern_type': 'seasonal',
                    'P1': [30,35],
                    'P1P': 100,
                    'P2':[0,1],
                    'P2P':0,
                    'P3':[0,1],
                    'P3P':0  
                }
                link_metric_policy_df=link_metric_policy_df.append(policy_entry,ignore_index=True)
                
            elif int(entity['interface_name'].split('-')[3]) in range(91,101):
                #this is the traffic out entry
                policy_entry = {
                    'metric': 'traffic_out_mbps',
                    'entity': entity['unique_id'],
                    'pattern_type': 'seasonal',
                    'P1': [30,35],
                    'P1P': 100,
                    'P2':[0,1],
                    'P2P':0,
                    'P3':[0,1],
                    'P3P':0  
                }
                link_metric_policy_df=link_metric_policy_df.append(policy_entry,ignore_index=True)
        elif entity['device_name'].split('-')[0]=='PE':
            if int(entity['interface_name'].split('-')[2]) == 1:
                if int(entity['device_name'].split('-')[1]) in range(1,51):
                
                    policy_entry = {
                        'metric': 'traffic_out_mbps',
                        'entity': entity['unique_id'],
                        'pattern_type': 'seasonal',
                        'P1': [20,25],
                        'P1P': 100,
                        'P2':[0,1],
                        'P2P':0,
                        'P3':[0,1],
                        'P3P':0  
                    }
                    link_metric_policy_df=link_metric_policy_df.append(policy_entry,ignore_index=True)
                elif int(entity['device_name'].split('-')[1]) in range(51,59):
                    if int(entity['interface_name'].split('-')[3]) in range(1,4):
                        policy_entry = {
                            'metric': 'traffic_out_mbps',
                            'entity': entity['unique_id'],
                            'pattern_type': 'seasonal',
                            'P1': [80,85],
                            'P1P': 100,
                            'P2':[0,1],
                            'P2P':0,
                            'P3':[0,1],
                            'P3P':0  
                        }
                        link_metric_policy_df=link_metric_policy_df.append(policy_entry,ignore_index=True)
                    elif int(entity['interface_name'].split('-')[3]) in range(4,5):
                        policy_entry = {
                            'metric': 'traffic_out_mbps',
                            'entity': entity['unique_id'],
                            'pattern_type': 'seasonal',
                            'P1': [80,85],
                            'P1P': 60,
                            'P2':[20,25],
                            'P2P':30,
                            'P3':[5,10],
                            'P3P':10  
                        }
                        link_metric_policy_df=link_metric_policy_df.append(policy_entry,ignore_index=True)
                elif int(entity['device_name'].split('-')[1]) in range(59,101):
                    policy_entry = {
                            'metric': 'traffic_out_mbps',
                            'entity': entity['unique_id'],
                            'pattern_type': 'seasonal',
                            'P1': [40,45],
                            'P1P': 80,
                            'P2':[100,105],
                            'P2P':10,
                            'P3':[0,5],
                            'P3P':10  
                    }
                    link_metric_policy_df=link_metric_policy_df.append(policy_entry,ignore_index=True)
            elif int(entity['interface_name'].split('-')[2]) == 2:
                policy_entry = {
                            'metric': 'traffic_out_mbps',
                            'entity': entity['unique_id'],
                            'pattern_type': 'seasonal',
                            'P1': [10,20],
                            'P1P': 80,
                            'P2':[30,40],
                            'P2P':10,
                            'P3':[50,60],
                            'P3P':10  
                }
                link_metric_policy_df=link_metric_policy_df.append(policy_entry,ignore_index=True)
        elif entity['device_name'].split('-')[0]=='E':
            if entity['interface_name'].split('-')[0] == 'et':
                if entity['device_name'].split('-')[1] in [1,100]:
                    policy_entry = {
                            'metric': 'traffic_out_mbps',
                            'entity': entity['unique_id'],
                            'pattern_type': 'seasonal',
                            'P1': [40,60],
                            'P1P': 80,
                            'P2':[30,40],
                            'P2P':15,
                            'P3':[0,1],
                            'P3P':5  
                    }
                    link_metric_policy_df=link_metric_policy_df.append(policy_entry,ignore_index=True)
                else:
                    policy_entry = {
                            'metric': 'traffic_out_mbps',
                            'entity': entity['unique_id'],
                            'pattern_type': 'seasonal',
                            'P1': [10,20],
                            'P1P': 80,
                            'P2':[30,40],
                            'P2P':15,
                            'P3':[0,1],
                            'P3P':5  
                    }
                    link_metric_policy_df=link_metric_policy_df.append(policy_entry,ignore_index=True)
            if entity['interface_name'].split('-')[0] == 'tun':
                if entity['device_name'].split('-')[1] in [1,100]:
                    if int(entity['interface_name'].split('-')[1]) not in [31,32]:
                        policy_entry = {
                            'metric': 'traffic_out_mbps',
                            'entity': entity['unique_id'],
                            'pattern_type': 'seasonal',
                            'P1': [5,6],
                            'P1P': 90,
                            'P2':[30,35],
                            'P2P':8,
                            'P3':[0,1],
                            'P3P':2  
                        }
                        link_metric_policy_df=link_metric_policy_df.append(policy_entry,ignore_index=True)
                    else:
                        policy_entry = {
                            'metric': 'traffic_out_mbps',
                            'entity': entity['unique_id'],
                            'pattern_type': 'seasonal',
                            'P1': [20,21],
                            'P1P': 100,
                            'P2':[0,1],
                            'P2P':0,
                            'P3':[0,1],
                            'P3P':0  
                        }
                        link_metric_policy_df=link_metric_policy_df.append(policy_entry,ignore_index=True)
                else:
                    policy_entry = {
                            'metric': 'traffic_out_mbps',
                            'entity': entity['unique_id'],
                            'pattern_type': 'seasonal',
                            'P1': [5,6],
                            'P1P': 90,
                            'P2':[30,35],
                            'P2P':8,
                            'P3':[0,1],
                            'P3P':2  
                    }
                    link_metric_policy_df=link_metric_policy_df.append(policy_entry,ignore_index=True)
    return link_metric_policy_df
                        
        




def stationary_gen(policy):
    random_number = np.random.randint(0,100)
    if random_number < policy['P1P']:
        #apply pattern 1
        pattern = 'P1'
    elif random_number >= policy['P1P'] and random_number < (policy['P1P']+policy['P2P']):
       #apply pattern 2
        pattern = 'P2'
    else:
        #apply pattern 3
        pattern = 'P3'            
    value = np.random.randint(policy[pattern][0],policy[pattern][1])
    return value


# In[21]:


def start_of_period(target_time,period,time_delta,offset = 0):
    # period options supported: minute, hour, day, week, month, year
    time_now = target_time-timedelta(minutes=offset)
    
    if period == 'minute':
        seconds_from_last_period = (time_now.minute % 1)*60 + time_now.second
        
    elif period == 'hour':
        seconds_from_last_period = time_now.minute*60 + time_now.second
    elif period == 'day':
        seconds_from_last_period = time_now.hour*3600 + time_now.minute*60 + time_now.second
    elif period == 'week':
        seconds_from_last_period = time_now.weekday()*24*3600 + time_now.hour*3600 + time_now.minute*60 + time_now.second
    elif period == 'month':
        seconds_from_last_period = time_now.day*24*3600 + time_now.hour*3600 + time_now.minute*60 + time_now.second
    elif period == 'year':
        days_of_the_year = time_now.timetuple().tm_yday
        seconds_from_last_period = days_of_the_year**24*3600 + time_now.hour*3600 + time_now.minute*60 + time_now.second
    
    
    start_of_period = time_now - timedelta(seconds=seconds_from_last_period)
    n_periods = int((time_now-start_of_period).total_seconds()/(60*time_delta))-1 
    if (time_now - start_of_period)<timedelta(minutes=time_delta):
        return True,n_periods
    else:
        return False,n_periods




def in_period(target_time,period,duration):
    # period options supported: minute, hour, day, week, month, year
    time_now = target_time
    
    if period == 'minute':
        seconds_from_last_period = (time_now.minute % 1)*60 + time_now.second 
    elif period == 'hour':
        seconds_from_last_period = time_now.minute*60 + time_now.second
    elif period == 'day':
        seconds_from_last_period = time_now.hour*3600 + time_now.minute*60 + time_now.second
    elif period == 'week':
        seconds_from_last_period = time_now.weekday()*24*3600 + time_now.hour*3600 + time_now.minute*60 + time_now.second
    elif period == 'month':
        seconds_from_last_period = time_now.day*24*3600 + time_now.hour*3600 + time_now.minute*60 + time_now.second
    elif period == 'year':
        days_of_the_year = time_now.timetuple().tm_yday
        seconds_from_last_period = days_of_the_year**24*3600 + time_now.hour*3600 + time_now.minute*60 + time_now.second
    
    
    start_of_period = time_now - timedelta(seconds=seconds_from_last_period)
    if (time_now - start_of_period)<timedelta(minutes=duration):
        return True
    else:
        return False




def convert_to_minutes(target_time,period):
    time_now = target_time
    if period == 'minute':
        period_minutes = 1
        
    elif period == 'hour':
        period_minutes = 60
    elif period == 'day':
        period_minutes = 24*60
    elif period == 'week':
        period_minutes = 24*60*7
    elif period == 'month':
        period_minutes = monthrange(time_now.year, time_now.month)[1]*24*60
    elif period == 'year':
        period_minutes = 365*24*60
    return period_minutes





def trending_gen(target_time,policy,time_delta):
    if len(policy['P1'])>3:
        if policy['P1'][3]=='seasonal':
            start_value = seasonal_gen(target_time,policy)
            delta_value = policy['P1'][4]
        else:
            start_value = stationary(policy)
            delta_value = policy['P1'][4]
    else:
        start_value = policy['P1'][0]
        end_value = policy['P1'][1]
        delta_value = end_value-start_value
        
    period = policy['P1'][2]
    start_new_period,n_segments = start_of_period(target_time,period,time_delta)
    increment = (delta_value)/(convert_to_minutes(target_time,period)/time_delta)*(1+np.random.random()*0.01)
    value = start_value*(1+np.random.random()*0.01) + increment*n_segments 
    return value




#seasonality weights for 15 minutes period throughout a day
            #   0:15         1:00                2:00              3:00                4:00                5:00               6:00              7:00            8:00            9:00              10:00           11:00       12:00          13:00.         14:00.          15:00           16:00.          17:00.          18:00           19:00           20:00           21:00.          22:00           23:00          00:00
daily_season = [0.2,0.2,0.18,0.15,0.13,0.13,0.11,0.1,0.1,0.08,0.08,0.07,0.07,0.06,0.06,0.05,0.06,0.06,0.08,0.1,0.11,0.14,0.16,0.18,0.2,0.3,0.35,0.4,0.5,0.6,0.7,0.8,0.9,1.1,1.3,1.35,1.37,1.5,1.6,1.8,1.9,2.1,2.2,2.3,2.5,2.7,2.9,3.0,3.2,3.5,3.6,3.7,3.8,4,4.3,4.2,4.4,4.6,4.5,4.3,4.2,4.2,4.1,4.3,4.5,4.6,4.8,4.8,5.0,5.1,5.3,5.5,5.6,5.5,5.4,5.6,5.3,5.2,4.8,4.3,4.0,3.8,3.6,3.5,3.3,3.1,2.8,2.4,2.1,1.6,1.0,0.8,0.4,0.3,0.2]

weekly_season =[1,1.2,1.3,1.2,1.1,0.6,0.4]




def seasonal_gen(target_time,policy):
    time_now = target_time
    start_of_day,n_segments = start_of_period(target_time,'day',15)
    daily_weight = daily_season[n_segments]*(1+np.random.random()*0.05)
    weekly_weight = weekly_season[time_now.weekday()]*(1+np.random.random()*0.05)
    value = stationary_gen(policy)*daily_weight*weekly_weight
    return value




def generate_event_templates():
    event_templates = pd.DataFrame(columns=event_template_labels)

    event_template_entry = {
        'event_id': 1,
        'event_name': 'interface_down',
        'event_type': 'unstructured',
        'scope': 'interface',
        'fields': ['device_name','interface_name','link_id'],
        'field_map': ['device_name','interface_name','link_id'],
        'severity': 'error',
        'message': "##timestamp##: if_mgr[##random##]: %INTF-STATE_MGR-3-STATE_CHANGE_EVENT : Interface changed state to down: ##interface_name## in device ##device_name##"
    }
    event_templates = event_templates.append(event_template_entry,ignore_index=True)
    event_template_entry = {
        'event_id': 2,
        'event_name': 'interface_up',
        'event_type': 'unstructured',
        'scope': 'interface',
        'fields': ['device_name','interface_name','link_id'],
        'field_map': ['device_name','interface_name','link_id'],
        'severity': 'info',
        'message': "##timestamp##: if_mgr[##random##]: %INTF-STATE_MGR-3-STATE_CHANGE_EVENT : Interface changed state to up: ##interface_name## in device ##device_name##"


    }
    event_templates = event_templates.append(event_template_entry,ignore_index=True)
    
    event_template_entry = {
        'event_id': 3,
        'event_name': 'bgp_session_down',
        'event_type': 'unstructured',
        'scope': 'interface',
        'fields': ['device_name','local_address','remote_peer_address','remote_id'],
        'field_map': ['device_name','interface_ip_address','peer_interface_ip_address','peer_device_name'],
        'severity': 'critical',
        'message': "##timestamp##: bgp_mgr[##random##]: %BGP-STATE_MGR-3-STATE_CHANGE_EVENT : BGP session to ##remote_peer_address## changed state to down in device ##device_name##"

    }
    event_templates = event_templates.append(event_template_entry,ignore_index=True)
    
    event_template_entry = {
        'event_id': 4,
        'event_name': 'bgp_session_up',
        'event_type': 'unstructured',
        'scope': 'interface',
        'fields': ['device_name','local_address','remote_peer_address','remote_id'],
        'field_map': ['device_name','interface_ip_address','peer_interface_ip_address','peer_device_name'],
        'severity': 'info',
        'message': "##timestamp##: bgp_mgr[##random##]: %BGP-STATE_MGR-3-STATE_CHANGE_EVENT : BGP session to ##remote_peer_address## changed state to up in device ##device_name##"


    }
    event_templates = event_templates.append(event_template_entry,ignore_index=True)
    
    event_template_entry = {
        'event_id': 5,
        'event_name': 'warning: hardware fault',
        'event_type': 'structured',
        'scope': 'device',
        'fields': ['device_name','device_ip','sw_version','hw_revision','device_role','device_vendor','device_model'],
        'field_map': ['device_name','ip_address','version','hw_revision','role','vendor','model'],
        'severity': 'critical'
    }
    event_templates = event_templates.append(event_template_entry,ignore_index=True)
    
    event_template_entry = {
        'event_id': 6,
        'event_name': 'hardware_fault_log',
        'event_type': 'unstructured',
        'scope': 'device',
        'fields': ['device_name','ip_address','hw_revision'],
        'field_map': ['device_name','ip_address','hw_revision'],
        'severity': 'critical',
        'message': "##timestamp##: shelf_mgr[##random##]: %INFRA-SHELF_MGR-3-HW_FAILURE_EVENT : HW failure event HW_EVENT_FAILURE, event_reason_str 'No Input or HW Power Failure' for device ##device_name## with hw revision ##hw_revision##"
    }
    event_templates = event_templates.append(event_template_entry,ignore_index=True)
    
    event_template_entry = {
        'event_id': 7,
        'event_name': 'high_temperature_log',
        'event_type': 'unstructured',
        'scope': 'device',
        'fields': ['device_name','ip_address','hw_revision'],
        'field_map': ['device_name','ip_address','hw_revision'],
        'severity': 'warning',
        'message': "##timestamp##: shelf_mgr[##random##]: %INFRA-SHELF_MGR-3-HW_HIGH_TEMP : HW warning event HW_EVENT_FAILURE, event_reason_str 'High Temperature' for device ##device_name## with hw revision ##hw_revision##"
    }
    event_templates = event_templates.append(event_template_entry,ignore_index=True)

    event_template_entry = {
        'event_id': 8,
        'event_name': 'user_login_log',
        'event_type': 'unstructured',
        'scope': 'device',
        'fields': ['device_name','ip_address'],
        'field_map': ['device_name','ip_address'],
        'severity': 'info',
        'message': "##timestamp##: exec[##random##]: %SECURITY-LOGIN-6-AUTHEN_SUCCESS : Successfully authenticated user 'uid##random##' from 'console' on ##device_name##"
    }
    event_templates = event_templates.append(event_template_entry,ignore_index=True)
    
    event_template_entry = {
        'event_id': 9,
        'event_name': 'user_login_failure_log',
        'event_type': 'unstructured',
        'scope': 'device',
        'fields': ['device_name','ip_address'],
        'field_map': ['device_name','ip_address'],
        'severity': 'info',
        'message': "##timestamp##: exec[##random##]: %MGBL-exec-3-LOGIN_AUTHEN : Login Authentication failed. Exiting.."
    }
    event_templates = event_templates.append(event_template_entry,ignore_index=True)
    
    event_template_entry = {
        'event_id': 10,
        'event_name': 'config_change_log',
        'event_type': 'unstructured',
        'scope': 'device',
        'fields': ['device_name','ip_address'],
        'field_map': ['device_name','ip_address'],
        'severity': 'info',
        'message': "##timestamp##: config[##random##]: %MGBL-CONFIG-6-DB_COMMIT : Configuration committed by user 'UID##random##'. Use 'show configuration commit changes ##random## to view the changes"
    }
    event_templates = event_templates.append(event_template_entry,ignore_index=True)
    
    
    event_template_entry = {
        'event_id': 11,
        'event_name': 'user_logout_log',
        'event_type': 'unstructured',
        'scope': 'device',
        'fields': ['device_name','ip_address'],
        'field_map': ['device_name','ip_address'],
        'severity': 'info',
        'message': "##timestamp##: SSHD_[##random##]: %SECURITY-SSHD-6-INFO_USER_LOGOUT : User UID##random## from ##device_name## logged out on 'vty0'"
    }
    event_templates = event_templates.append(event_template_entry,ignore_index=True)
    
    event_template_entry = {
        'event_id': 12,
        'event_name': 'system_fan_log',
        'event_type': 'unstructured',
        'scope': 'device',
        'fields': ['device_name','ip_address'],
        'field_map': ['device_name','ip_address'],
        'severity': 'critical',
        'message': "##timestamp##: %ENVMON-2-SYSTEM_FAN_FAILED: Critical Warning: System Fan has failed. Please replace the fan to prevent system overheating"
    }
    event_templates = event_templates.append(event_template_entry,ignore_index=True)
    
    event_template_entry = {
        'event_id': 13,
        'event_name': 'interface_local_fault',
        'event_type': 'unstructured',
        'scope': 'interface',
        'fields': ['device_name','interface_name','link_id'],
        'field_map': ['device_name','interface_name','link_id'],
        'severity': 'critical',
        'message': "##timestamp##: npu_drvr[##random##]: %PLATFORM-VETH_PD-2-RX_FAULT : Interface ##interface_name##, Detected Local Fault"
    }
    event_templates = event_templates.append(event_template_entry,ignore_index=True)

    event_template_entry = {
        'event_id': 14,
        'event_name': 'very_high_temperature_log',
        'event_type': 'unstructured',
        'scope': 'device',
        'fields': ['device_name','ip_address','hw_revision'],
        'field_map': ['device_name','ip_address','hw_revision'],
        'severity': 'warning',
        'message': "##timestamp##: %ENVMON-2-IN_OUTLET_OVERTEMP: ##device_name## Warning: Intake Left Temperature 43C Exceeds 42C. Please resolve system cooling to prevent system damage"
    }
    event_templates = event_templates.append(event_template_entry,ignore_index=True)
    
    event_template_entry = {
        'event_id': 15,
        'event_name': 'interface_optics_fault',
        'event_type': 'unstructured',
        'scope': 'interface',
        'fields': ['device_name','interface_name','link_id'],
        'field_map': ['device_name','interface_name','link_id'],
        'severity': 'critical',
        'message': "##timestamp##: lda_server[##random##]: %PKT_INFRA-FM-3-FAULT_MAJOR : ALARM_MAJOR :OPTICS RX POWER LANE-3 HIGH WARNING :CLEAR ##interface_name##"
    }
    event_templates = event_templates.append(event_template_entry,ignore_index=True)
    
    event_templates.set_index('event_id',inplace=True)
    return event_templates
    
    




def generate_event_policy(event_templates,device_inventory_df,interface_inventory_df):
    event_policy = pd.DataFrame(columns=event_policy_labels)


    for i,entity in device_inventory_df.iterrows():
        if entity['device_name'].split('-')[0]=='PE':
            if int(entity['device_name'].split('-')[1]) in range(1,51):
                event_policy_entry = {
                    'policy_name':'low hardware faults in PEs',
                    'event_id': 5,
                    'period': 'minute',
                    'probability': 20,
                    'entity_table': 'devices',
                    'entity_column': 'device_name',
                    'entity_name': entity['device_name'],
                    'fields': [entity['device_name'],entity['ip_address'],entity['version'],entity['hw_revision'],entity['role'],entity['vendor'],entity['model']]                   
                }
                event_policy = event_policy.append(event_policy_entry,ignore_index=True)

            elif int(entity['device_name'].split('-')[1]) in range(51,59):
                event_policy_entry = {
                    'policy_name':'medium hardware faults in PEs',
                    'event_id': 5,
                    'period': 'minute',
                    'probability': 40,
                    'entity_table': 'devices',
                    'entity_column': 'device_name',
                    'entity_name': entity['device_name'],
                    'fields': [entity['device_name'],entity['ip_address'],entity['version'],entity['hw_revision'],entity['role'],entity['vendor'],entity['model']]                   
                }
                event_policy = event_policy.append(event_policy_entry,ignore_index=True)
            elif int(entity['device_name'].split('-')[1]) in range(59,61):
                event_policy_entry = {
                    'policy_name':'high hardware faults in PEs',
                    'event_id': 5,
                    'period': 'minute',
                    'probability': 90,
                    'entity_table': 'devices',
                    'entity_column': 'device_name',
                    'entity_name': entity['device_name'],
                    'fields': [entity['device_name'],entity['ip_address'],entity['version'],entity['hw_revision'],entity['role'],entity['vendor'],entity['model']]                   
                }
                event_policy = event_policy.append(event_policy_entry,ignore_index=True)
            else:
                event_policy_entry = {
                    'policy_name':'all the other PEs devices',
                    'event_id': 5,
                    'period': 'minute',
                    'probability': 15,
                    'entity_table': 'devices',
                    'entity_column': 'device_name',
                    'entity_name': entity['device_name'],
                    'fields': [entity['device_name'],entity['ip_address'],entity['version'],entity['hw_revision'],entity['role'],entity['vendor'],entity['model']]                   
                }
                event_policy = event_policy.append(event_policy_entry,ignore_index=True)
        else:
            event_policy_entry = {
                    'policy_name':'hardware fault',
                    'event_id': 6,
                    'period': 'minute',
                    'probability': 5,
                    'entity_table': 'devices',
                    'entity_column': 'device_name',
                    'entity_name': entity['device_name'],
                    'fields': [entity['device_name'],entity['ip_address'],entity['hw_revision']]                   
                }
            event_policy = event_policy.append(event_policy_entry,ignore_index=True)
            event_policy_entry = {
                    'policy_name':'high temperature',
                    'event_id': 7,
                    'period': 'minute',
                    'probability': 40,
                    'entity_table': 'devices',
                    'entity_column': 'device_name',
                    'entity_name': entity['device_name'],
                    'fields': [entity['device_name'],entity['ip_address'],entity['hw_revision']]                   
                }
            event_policy = event_policy.append(event_policy_entry,ignore_index=True)
            event_policy_entry = {
                    'policy_name':'user login',
                    'event_id': 8,
                    'period': 'minute',
                    'probability': 15,
                    'entity_table': 'devices',
                    'entity_column': 'device_name',
                    'entity_name': entity['device_name'],
                    'fields': [entity['device_name'],entity['ip_address']]                   
                }
            event_policy = event_policy.append(event_policy_entry,ignore_index=True)
            event_policy_entry = {
                    'policy_name':'login failure',
                    'event_id': 9,
                    'period': 'minute',
                    'probability': 20,
                    'entity_table': 'devices',
                    'entity_column': 'device_name',
                    'entity_name': entity['device_name'],
                    'fields': [entity['device_name'],entity['ip_address']]                   
                }
            event_policy = event_policy.append(event_policy_entry,ignore_index=True)
            event_policy_entry = {
                    'policy_name':'config change',
                    'event_id': 10,
                    'period': 'minute',
                    'probability': 10,
                    'entity_table': 'devices',
                    'entity_column': 'device_name',
                    'entity_name': entity['device_name'],
                    'fields': [entity['device_name'],entity['ip_address']]                   
                }
            event_policy = event_policy.append(event_policy_entry,ignore_index=True)
            event_policy_entry = {
                    'policy_name':'user logout',
                    'event_id': 11,
                    'period': 'minute',
                    'probability': 10,
                    'entity_table': 'devices',
                    'entity_column': 'device_name',
                    'entity_name': entity['device_name'],
                    'fields': [entity['device_name'],entity['ip_address']]                   
                }
            event_policy = event_policy.append(event_policy_entry,ignore_index=True)
            
            event_policy_entry = {
                    'policy_name':'system fan issue',
                    'event_id': 12,
                    'period': 'minute',
                    'probability': 10,
                    'entity_table': 'devices',
                    'entity_column': 'device_name',
                    'entity_name': entity['device_name'],
                    'fields': [entity['device_name'],entity['ip_address']]                   
                }
            event_policy = event_policy.append(event_policy_entry,ignore_index=True)
            
            event_policy_entry = {
                    'policy_name':'very high temperature',
                    'event_id': 14,
                    'period': 'minute',
                    'probability': 30,
                    'entity_table': 'devices',
                    'entity_column': 'device_name',
                    'entity_name': entity['device_name'],
                    'fields': [entity['device_name'],entity['ip_address'],entity['hw_revision']]                   
                }
            event_policy = event_policy.append(event_policy_entry,ignore_index=True)
   
            
    for i,entity in interface_inventory_df.iterrows():
        event_policy_entry = {
                    'policy_name':'interface down',
                    'event_id': 1,
                    'period': 'minute',
                    'probability': 5,
                    'entity_table': 'interfaces',
                    'entity_column': 'link_id',
                    'entity_name': entity['link_id'],
                    'fields': [entity['device_name'],entity['interface_name'],entity['link_id']]                   
        }
        event_policy = event_policy.append(event_policy_entry,ignore_index=True)
        event_policy_entry = {
                    'policy_name':'interface up',
                    'event_id': 2,
                    'period': 'minute',
                    'probability': 1,
                    'entity_table': 'interfaces',
                    'entity_column': 'link_id',
                    'entity_name': entity['link_id'],
                    'fields': [entity['device_name'],entity['interface_name'],entity['link_id']]                   
        }
        
        event_policy = event_policy.append(event_policy_entry,ignore_index=True)
        event_policy_entry = {
                    'policy_name':'bgp down',
                    'event_id': 3,
                    'period': 'minute',
                    'probability': 1,
                    'entity_table': 'interfaces',
                    'entity_column': 'link_id',
                    'entity_name': entity['link_id'],
                    'fields': [entity['device_name'],entity['interface_ip_address'],entity['peer_interface_ip_address'],entity['peer_device_name']]                   
        }
        event_policy = event_policy.append(event_policy_entry,ignore_index=True)
        event_policy_entry = {
                    'policy_name':'bgp up',
                    'event_id': 4,
                    'period': 'minute',
                    'probability': 1,
                    'entity_table': 'interfaces',
                    'entity_column': 'link_id',
                    'entity_name': entity['link_id'],
                    'fields': [entity['device_name'],entity['interface_ip_address'],entity['peer_interface_ip_address'],entity['peer_device_name']]                   
        }
        event_policy = event_policy.append(event_policy_entry,ignore_index=True)
        
        event_policy_entry = {
                    'policy_name':'interface local fault',
                    'event_id': 13,
                    'period': 'minute',
                    'probability': 1,
                    'entity_table': 'interfaces',
                    'entity_column': 'link_id',
                    'entity_name': entity['link_id'],
                    'fields': [entity['device_name'],entity['interface_name'],entity['link_id']]                   
        }
        event_policy = event_policy.append(event_policy_entry,ignore_index=True)
        
        event_policy_entry = {
                    'policy_name':'interface optics fault',
                    'event_id': 15,
                    'period': 'minute',
                    'probability': 1,
                    'entity_table': 'interfaces',
                    'entity_column': 'link_id',
                    'entity_name': entity['link_id'],
                    'fields': [entity['device_name'],entity['interface_name'],entity['link_id']]                   
        }
        event_policy = event_policy.append(event_policy_entry,ignore_index=True)
        
    return event_policy




def generate_event(target_time,event_policy_entry,event_templates):
    fields = dict()
    event_id = event_policy_entry['event_id']
    event_type = event_templates.loc[event_id,'event_type']
    event_template = event_templates.loc[event_id,:]
    if event_type == 'structured':
        for i in range(len(event_policy_entry['fields'])):
            fields[event_templates.loc[event_id,'fields'][i]]=event_policy_entry['fields'][i]
    
        event_object = {
            'timestamp': timegm(target_time.timetuple()),
            'event_name': event_templates.loc[event_id,'event_name'],
            'source': event_policy_entry['entity_name'],
            'fields': json.dumps([fields]),
            'severity': event_templates.loc[event_id,'severity']
        }
    elif event_type == 'unstructured':
        for i in range(len(event_policy_entry['fields'])):
            fields[event_templates.loc[event_id,'fields'][i]]=event_policy_entry['fields'][i]
        message_components = event_template['message'].split('##')
        generated_message = ''
        fields_list = event_template['fields']
        for element in message_components:
            if element == 'timestamp':
                generated_message += datetime.fromtimestamp(timegm(target_time.timetuple())).strftime('%Y-%m-%d %H:%M:%S')
            elif element == 'random':
                generated_message += str(np.random.randint(0,10000))
            elif element in fields_list:
                i = fields_list.index(element)
                generated_message += str(event_policy_entry['fields'][i])
            else:
                generated_message += element
        event_object = {
            'timestamp': timegm(target_time.timetuple()),
            'event_name': event_templates.loc[event_id,'event_name'],
            'source': event_policy_entry['entity_name'],
            'fields': json.dumps([fields]),
            'severity': event_templates.loc[event_id,'severity'],
            'message': generated_message
            
        }
    return event_object



def generate_incident_policy():
    incident_policy_df = pd.DataFrame(columns=incident_policy_labels)
    
    
    incident_1_entry = {
        'incident_name': 'event sequence test',
        'period': 'minute',
        'entity_table': 'devices',
        'entity_column': 'device_name',
        'entity_name': 'PE-57',
        'impact_type':'event',
        'impact_details': ['hardware_fault_log'],
    }
    
    incident_policy_df = incident_policy_df.append(incident_1_entry,ignore_index=True)
    
    incident_1_entry = {
        'incident_name': 'event sequence test',
        'period': 'minute',
        'entity_table': 'interfaces',
        'entity_column': 'device_name',
        'entity_name': 'PE-57',
        'impact_type':'event',
        'impact_details': ['interface_down',1,'bgp_session_down',2,'interface_up',3,'bgp_session_up'],
    }
    
    incident_policy_df = incident_policy_df.append(incident_1_entry,ignore_index=True)
    
    incident_1_entry = {
        'incident_name': 'optics failure in PE-10',
        'period': 'minute',
        'entity_table': 'interfaces',
        'entity_column': 'device_name',
        'entity_name': 'PE-10',
        'impact_type':'event',
        'impact_details': ['interface_optics_fault',0,'interface_local_fault',0,'interface_down',1,'bgp_session_down',3,'interface_up',4,'bgp_session_up'],
    }
    
    incident_policy_df = incident_policy_df.append(incident_1_entry,ignore_index=True)
    
    incident_1_entry = {
        'incident_name': 'optics failure in PE-10',
        'period': 'minute',
        'entity_table': 'interfaces',
        'entity_column': 'peer_device_name',
        'entity_name': 'PE-10',
        'impact_type':'event',
        'impact_details': ['interface_optics_fault',0,'interface_local_fault',0,'interface_down',1,'bgp_session_down',3,'interface_up',4,'bgp_session_up'],
    }
    
    incident_policy_df = incident_policy_df.append(incident_1_entry,ignore_index=True)
    
    


    return incident_policy_df




def run_incidents_on_metrics(target_time,incident_policy,metrics,entity_type,metric_list):
    updated_metrics = []
    impact_mask_1 = incident_policy['impact_type']=='metric'
    impact_mask_2 = incident_policy['entity_table']==entity_type
    impact_mask = np.logical_and(impact_mask_1,impact_mask_2)
    target_incidents = incident_policy[impact_mask]
    for metric_object in metrics:
        for i,impact in target_incidents.iterrows():
            if metric_object[impact['entity_column']]==impact['entity_name']:
                if in_period(target_time,impact['period'],impact['impact_details'][2]):
                    if impact['impact_details'][0]=='all':
                        for metric in metric_list:
                            metric_object[metric]=impact['impact_details'][1]
                    else:
                        metric_object[impact['impact_details'][0]]=impact['impact_details'][1]
        updated_metrics.append(metric_object)
    return updated_metrics




def run_incidents_on_events(target_time,incident_policy,event_templates,time_delta,device_inventory,interface_inventory):
    new_event_list = []
    
    impact_mask = incident_policy['impact_type']=='event'
    target_incidents = incident_policy[impact_mask]
    for i,impact in target_incidents.iterrows():
        
        period = impact['period']
        event_required,n = start_of_period(target_time,period,time_delta,offset = 0)
        if event_required:
            event_name = impact['impact_details'][0]
            entity_column = impact['entity_column']
            entity_name = impact['entity_name']
            if impact['entity_table']=='devices':
                target_resources_mask = device_inventory.loc[:,entity_column]==entity_name
                target_resources = device_inventory[target_resources_mask]
            elif impact['entity_table']=='interfaces':
                target_resources_mask = interface_inventory.loc[:,entity_column]==entity_name
                target_resources = interface_inventory[target_resources_mask]
            for j,resource in target_resources.iterrows():
                event_template_mask = event_templates['event_name']==impact['impact_details'][0]
                template = event_templates.loc[event_template_mask,:]
                template_field_map = event_templates.loc[event_template_mask,'field_map'].values[0]
                event_id= template.index.values[0]
    
                field_list= [resource[x] for x in template_field_map]
                
                event_policy_entry = {
                    'policy_name':impact['incident_name'],
                    'event_id': event_id,
                    'period': period,
                    'probability': 100,
                    'entity_table': impact['entity_table'],
                    'entity_column': 'aux',
                    'entity_name': resource['device_name'],
                    'fields': field_list                   
                }
                new_event=generate_event(target_time,event_policy_entry,event_templates)
                new_event_list.append(new_event)
            if len(impact['impact_details'])>1:
                for w in range(int(len(impact['impact_details'])/2)):
                        p = w*2+1
                       
                        event_name = impact['impact_details'][p+1]
                        entity_column = impact['entity_column']
                        entity_name = impact['entity_name']
                        if impact['entity_table']=='devices':
                            target_resources_mask = device_inventory.loc[:,entity_column]==entity_name
                            target_resources = device_inventory[target_resources_mask]
                        elif impact['entity_table']=='interfaces':
                            target_resources_mask = interface_inventory.loc[:,entity_column]==entity_name
                            target_resources = interface_inventory[target_resources_mask]
                        for j,resource in target_resources.iterrows():
                            event_template_mask = event_templates['event_name']==impact['impact_details'][p+1]
                            template = event_templates.loc[event_template_mask,:]
                            template_field_map = event_templates.loc[event_template_mask,'field_map'].values[0]
                            event_id= template.index.values[0]
                
                            field_list= [resource[x] for x in template_field_map]
                            event_policy_entry = {
                                'policy_name':impact['incident_name'],
                                'event_id': event_id,
                                'period': period,
                                'probability': 100,
                                'entity_table': impact['entity_table'],
                                'entity_column': 'aux',
                                'entity_name': resource['device_name'],
                                'fields': field_list                   
                            }
                            new_event=generate_event(target_time+timedelta(minutes=impact['impact_details'][p]),event_policy_entry,event_templates)
                            new_event_list.append(new_event)
        
    return new_event_list


# In[45]:


def generate_device_metrics(target_time,params):
    time_delta=params.get('time_delta')
    metric_list = []
    #device_inventory contains all devices on the use case and their labels
    device_inventory = generate_device_inventory()
    #device_metric_policy contains one entry per metric per device instructing how it should be generated
    device_metric_policy = generate_device_metric_policy(device_inventory)
    #for each device in the inventory, we run through the metric policies and generate the corresponding values
    for i,device in device_inventory.iterrows():
        policy_mask = device_metric_policy['entity']==device['device_name']
        target_metric_policies = device_metric_policy.loc[policy_mask,:]
        metric_object = dict()
        metric_object['timestamp']=timegm(target_time.timetuple())
        for i,metric_policy in target_metric_policies.iterrows():
            if metric_policy['pattern_type']=='stationary':
                metric_value = stationary_gen(metric_policy)
            elif metric_policy['pattern_type']=='trending':
                metric_value = trending_gen(target_time,metric_policy,time_delta)
            elif metric_policy['pattern_type']=='seasonal':
                metric_value = seasonal_gen(target_time,metric_policy)
            metric_object[metric_policy['metric']]=metric_value
        for col in device_inventory_labels:
            metric_object[col]=device[col]
        #every metric object contains the metrics per device along with all the labels required.
        metric_list.append(metric_object)
        #generate the table the contains the incidents we want to run against the generated metrics
        incident_policy = generate_incident_policy()
        
        final_metric_list = run_incidents_on_metrics(target_time,incident_policy,metric_list,'devices',device_metric_list)
    return final_metric_list

    


# In[46]:


def generate_interface_metrics(target_time,params):
    time_delta=params.get('time_delta')
    role_list = params.get('interface_role')
    metric_list = []
    #device_inventory contains all devices on the use case and their labels
    interface_inventory = generate_interface_inventory()
    #device_metric_policy contains one entry per metric per device instructing how it should be generated
    link_metric_policy = generate_link_metric_policy(interface_inventory)
    #for each link in the inventory, we run through the metric policies and generate the corresponding values
    for role in role_list:
        role_mask = interface_inventory['interface_role']==role
        target_interface_inventory = interface_inventory[role_mask]
        all_links = target_interface_inventory['link_id'].unique()
        for link in all_links:
            link_mask = interface_inventory['link_id']==link
            target_links = interface_inventory[link_mask]
            #print('Target links are:')
            #print(target_links)
            interface_a = target_links.iloc[0,:]
            interface_b = target_links.iloc[1,:]
            policy_mask_a = link_metric_policy['entity']==interface_a['unique_id']
            policy_mask_b = link_metric_policy['entity']==interface_b['unique_id']
            target_metric_policies_a = link_metric_policy.loc[policy_mask_a,:]
            target_metric_policies_b = link_metric_policy.loc[policy_mask_b,:]
            metric_object_a = dict()
            metric_object_b = dict()
            metric_object_a['timestamp']=timegm(target_time.timetuple())
            metric_object_b['timestamp']=timegm(target_time.timetuple())
            for i,metric_policy in target_metric_policies_a.iterrows():
                if metric_policy['pattern_type']=='stationary':
                    metric_value = stationary_gen(metric_policy)
                elif metric_policy['pattern_type']=='trending':
                    metric_value = trending_gen(target_time,metric_policy,time_delta)
                elif metric_policy['pattern_type']=='seasonal':
                    metric_value = seasonal_gen(target_time,metric_policy)
                metric_object_a[metric_policy['metric']]=metric_value
                metric_object_b['traffic_in_mbps']=metric_value
            for col in interface_inventory_labels:
                metric_object_a[col]=interface_a[col]
            for i,metric_policy in target_metric_policies_b.iterrows():
                if metric_policy['pattern_type']=='stationary':
                    metric_value = stationary_gen(metric_policy)
                elif metric_policy['pattern_type']=='trending':
                    metric_value = trending_gen(target_time,metric_policy,time_delta)
                elif metric_policy['pattern_type']=='seasonal':
                    metric_value = seasonal_gen(target_time,metric_policy)
                metric_object_b[metric_policy['metric']]=metric_value
                metric_object_a['traffic_in_mbps']=metric_value
            for col in interface_inventory_labels:
                metric_object_b[col]=interface_b[col]
            
            #every metric object contains the metrics per interface along with all the labels required.
            metric_list.append(metric_object_a)
            metric_list.append(metric_object_b)
            #generate the table the contains the incidents we want to run against the generated metrics
        incident_policy = generate_incident_policy()
        
        final_metric_list = run_incidents_on_metrics(target_time,incident_policy,metric_list,'interfaces',interface_metric_list)
    return final_metric_list


# In[48]:


def generate_events(target_time,params):
    time_delta=params.get('time_delta')
    event_list = []
    #device_inventory contains all devices on the use case and their labels
    device_inventory = generate_device_inventory()
    interface_inventory = generate_interface_inventory()
    event_templates = generate_event_templates()
    event_policy = generate_event_policy(event_templates,device_inventory,interface_inventory)
    for i,entry in event_policy.iterrows():
        period = entry['period']
        event_required,n = start_of_period(target_time,period,time_delta,offset = 0)
        if event_required:
            random_number = np.random.randint(0,100)
            if random_number < entry['probability']:
                new_event=generate_event(target_time,entry,event_templates)
                event_list.append(new_event)
    incident_policy = generate_incident_policy()
    incident_events = run_incidents_on_events(target_time,incident_policy,event_templates,time_delta,device_inventory,interface_inventory)
    event_list += incident_events
    return event_list




def get_device_inventory(parameters):
    device_inventory = generate_device_inventory()
    inventory_list = []
    label_list = device_inventory.columns
    for i,entry in device_inventory.iterrows():
        inventory_entry = dict()
        for label in label_list:
            inventory_entry[label]=entry[label]
        inventory_list.append(inventory_entry)
    return inventory_list
        
        




def get_interface_inventory(parameters):
    interface_inventory = generate_interface_inventory()
    inventory_list = []
    label_list = interface_inventory.columns
    for i,entry in interface_inventory.iterrows():
        inventory_entry = dict()
        for label in label_list:
            inventory_entry[label]=entry[label]
        inventory_list.append(inventory_entry)
    return inventory_list




def generate_target_device_metric(target_time,params,target_device,target_metric,device_inventory,device_metric_policy):
    time_delta=params.get('time_delta')
    metric_list = []
    
    device_inventory_mask = device_inventory['device_name']==target_device
    device = device_inventory[device_inventory_mask].iloc[0,:]
    
    device_mask = device_metric_policy['entity']==target_device
    metric_mask = device_metric_policy['metric']==target_metric
    policy_mask = np.logical_and(device_mask,metric_mask)
    target_metric_policies = device_metric_policy.loc[policy_mask,:]
    metric_object = dict()
    metric_object['timestamp']=timegm(target_time.timetuple())
    for i,metric_policy in target_metric_policies.iterrows():
        if metric_policy['pattern_type']=='stationary':
            metric_value = stationary_gen(metric_policy)
        elif metric_policy['pattern_type']=='trending':
            metric_value = trending_gen(target_time,metric_policy,time_delta)
        elif metric_policy['pattern_type']=='seasonal':
            metric_value = seasonal_gen(target_time,metric_policy)
        metric_object[metric_policy['metric']]=metric_value
    for col in device_inventory_labels:
        metric_object[col]=device[col]
    #every metric object contains the metrics per device along with all the labels required.
    metric_list.append(metric_object)
    #generate the table the contains the incidents we want to run against the generated metrics
    incident_policy = generate_incident_policy()
    
    final_metric_list = run_incidents_on_metrics(target_time,incident_policy,metric_list,'devices',device_metric_list)
    return final_metric_list




def generate_device_metric_time_range(start_time,end_time,params,device_list,metric_list,device_filter = "none"):
    device_inventory = generate_device_inventory()
    device_metric_policy = generate_device_metric_policy(device_inventory)
    time_delta = params.get('time_delta')
    target_time = start_time
    if device_list == "none":
        target_keys = list(device_filter.keys())
        target_values = list(device_filter.values())
        target_mask = np.ones(device_inventory.shape[0])
        for i in range(len(target_keys)):
            condition = device_inventory[target_keys[i]]==target_values[i]
            target_mask = np.logical_and(target_mask,condition)
        target_entities = device_inventory[target_mask]
        target_device_list = target_entities['device_name'].tolist()
    elif device_list == "all":
        target_device_list = device_inventory.loc[:,'device_name'].tolist()
    else:
        target_device_list = device_list
    
    metric_object_list = []
    
    while target_time < end_time:
        for device in target_device_list:
            for metric in metric_list:
                metric_object = generate_target_device_metric(target_time,params,device,metric,device_inventory,device_metric_policy)
                metric_object_list.append(metric_object)
        target_time += timedelta(minutes=time_delta)
    metrics_df = pd.DataFrame(columns=metric_object[0].keys())
    for metric_object in metric_object_list:
        metrics_df=metrics_df.append(metric_object[0],ignore_index=True)
    return metrics_df


def generate_events_time_range(start_time,end_time,params,device_list,device_filter = "none",with_incidents=False):
    device_inventory = generate_device_inventory()
    interface_inventory = generate_interface_inventory()
    event_templates = generate_event_templates()
    event_policy = generate_event_policy(event_templates,device_inventory,interface_inventory)
    if with_incidents:
        incident_policy = generate_incident_policy()
    time_delta = params.get('time_delta')
    target_time = start_time
    if device_list == "none":
        target_keys = list(device_filter.keys())
        target_values = list(device_filter.values())
        target_mask = np.ones(device_inventory.shape[0])
        for i in range(len(target_keys)):
            condition = device_inventory[target_keys[i]]==target_values[i]
            target_mask = np.logical_and(target_mask,condition)
        target_entities = device_inventory[target_mask]
        target_device_list = target_entities['device_name'].tolist()
    elif device_list == "all":
        target_device_list = device_inventory.loc[:,'device_name'].tolist()
    else:
        target_device_list = device_list
    interface_mask = np.zeros(interface_inventory.shape[0])
    for device in target_device_list:
        interface_mask = np.logical_or(interface_mask,interface_inventory['device_name']==device)
    target_interface_list = interface_inventory[interface_mask]['link_id'].to_list()
    event_list = []
    while target_time < end_time:
        for i,entry in event_policy.iterrows():
            period = entry['period']
            if entry['entity_name'] in target_device_list or entry['entity_name'] in target_interface_list:
                event_required,n = start_of_period(target_time,period,time_delta,offset = 0)
                if event_required:
                    random_number = np.random.randint(0,100)
                    if random_number < entry['probability']:
                        new_event=generate_event(target_time,entry,event_templates)
                        event_list.append(new_event)
        if with_incidents:
            incident_events = run_incidents_on_events(target_time,incident_policy,event_templates,time_delta,device_inventory,interface_inventory)
            event_list += incident_events
        target_time += timedelta(minutes=time_delta)
        
    events_df = pd.DataFrame(columns=event_list[0].keys())
    for event_object in event_list:
        events_df=events_df.append(event_object,ignore_index=True)
    events_df = events_df.sort_values('timestamp',ascending=True)
    return events_df

def generate_interface_metric_time_range(start_time,end_time,params,device_list,device_filter = "none",with_incidents=False):
    device_inventory = generate_device_inventory()
    interface_inventory = generate_interface_inventory()
    interface_metric_policy = generate_link_metric_policy(interface_inventory)
    time_delta = params.get('time_delta')
    target_time = start_time
    if device_list == "none":
        target_keys = list(device_filter.keys())
        target_values = list(device_filter.values())
        target_mask = np.ones(device_inventory.shape[0])
        for i in range(len(target_keys)):
            condition = device_inventory[target_keys[i]]==target_values[i]
            target_mask = np.logical_and(target_mask,condition)
        target_entities = device_inventory[target_mask]
        target_device_list = target_entities['device_name'].tolist()
    elif device_list == "all":
        target_device_list = device_inventory.loc[:,'device_name'].tolist()
    else:
        target_device_list = device_list
    interface_target_mask = np.zeros(interface_inventory.shape[0])
    for dev in target_device_list:
        interface_target_mask = np.logical_or(interface_target_mask,interface_inventory['device_name']==dev)
    target_interface_inventory = interface_inventory[interface_target_mask]
    metric_object_list = []
    while target_time < end_time:
        metric_object = generate_interface_traffic_metrics(target_time,params,target_interface_inventory,interface_metric_policy,with_incidents)
        metric_object_list += metric_object
        target_time += timedelta(minutes=time_delta)
    
    metrics_df = pd.DataFrame(columns=metric_object_list[0].keys())
    for metric_object in metric_object_list:
        metrics_df=metrics_df.append(metric_object,ignore_index=True)
    return metrics_df

def generate_interface_traffic_metrics(target_time,params,interface_inventory,link_metric_policy,with_incidents=False):
    time_delta=params.get('time_delta')
    role_list = params.get('interface_role')
    metric_list = []
    for role in role_list:
        role_mask = interface_inventory['interface_role']==role
        target_interface_inventory = interface_inventory[role_mask]
        #print('Target interfaces:',target_interface_inventory)
        all_links = target_interface_inventory['link_id'].unique()
        for link in all_links:
            link_mask = interface_inventory['link_id']==link
            target_links = interface_inventory[link_mask]
            #print('Target links are:')
            #print(target_links)
            interface_a = target_links.iloc[0,:]
            interface_b = target_links.iloc[1,:]
            policy_mask_a = link_metric_policy['entity']==interface_a['unique_id']
            policy_mask_b = link_metric_policy['entity']==interface_b['unique_id']
            target_metric_policies_a = link_metric_policy.loc[policy_mask_a,:]
            target_metric_policies_b = link_metric_policy.loc[policy_mask_b,:]
            metric_object_a = dict()
            metric_object_b = dict()
            metric_object_a['timestamp']=timegm(target_time.timetuple())
            metric_object_b['timestamp']=timegm(target_time.timetuple())
            for i,metric_policy in target_metric_policies_a.iterrows():
                if metric_policy['pattern_type']=='stationary':
                    metric_value = stationary_gen(metric_policy)
                elif metric_policy['pattern_type']=='trending':
                    metric_value = trending_gen(target_time,metric_policy,time_delta)
                elif metric_policy['pattern_type']=='seasonal':
                    metric_value = seasonal_gen(target_time,metric_policy)
                metric_object_a[metric_policy['metric']]=metric_value
                metric_object_b['traffic_in_mbps']=metric_value
            for col in interface_inventory_labels:
                metric_object_a[col]=interface_a[col]
            for i,metric_policy in target_metric_policies_b.iterrows():
                if metric_policy['pattern_type']=='stationary':
                    metric_value = stationary_gen(metric_policy)
                elif metric_policy['pattern_type']=='trending':
                    metric_value = trending_gen(target_time,metric_policy,time_delta)
                elif metric_policy['pattern_type']=='seasonal':
                    metric_value = seasonal_gen(target_time,metric_policy)
                metric_object_b[metric_policy['metric']]=metric_value
                metric_object_a['traffic_in_mbps']=metric_value
            for col in interface_inventory_labels:
                metric_object_b[col]=interface_b[col]
            
            metric_list.append(metric_object_a)
            metric_list.append(metric_object_b)
        if with_incidents:
            incident_policy = generate_incident_policy()
            
            final_metric_list = run_incidents_on_metrics(target_time,incident_policy,metric_list,'interfaces',interface_metric_list)
        else:
            final_metric_list = metric_list
    return final_metric_list


def find_config_start(config_lines, start_sequence):
  i=0
  config_found = np.False_
  while not config_found:
    if start_sequence in config_lines[i]:
      config_found = True
      config_index = i+1
    else:
      i+=1
  return config_index

def get_lines(config_file):
  file_handle = open(config_file, 'r')
  config_lines = file_handle.readlines() 
  return config_lines

def get_config_lines(config_file):
  file_handle = open(config_file, 'r')
  config_lines = file_handle.readlines() 
  
  return config_lines
    
def generate_device_configs(config_template_file,device_list,device_filter = "none"):
    config_template = get_config_lines(config_template_file)
    device_inventory = generate_device_inventory()
    interface_inventory = generate_interface_inventory()
    if device_list == "none":
        target_keys = list(device_filter.keys())
        target_values = list(device_filter.values())
        target_mask = np.ones(device_inventory.shape[0])
        for i in range(len(target_keys)):
            condition = device_inventory[target_keys[i]]==target_values[i]
            target_mask = np.logical_and(target_mask,condition)
        target_entities = device_inventory[target_mask]
        target_device_list = target_entities['device_name'].tolist()
    elif device_list == "all":
        target_device_list = device_inventory.loc[:,'device_name'].tolist()
    else:
        target_device_list = device_list
    target_device_mask = np.zeros(device_inventory.shape[0])
    for dev in target_device_list:
        target_device_mask = np.logical_or(target_device_mask,device_inventory['device_name']==dev)
    target_device_inventory = device_inventory[target_device_mask]
    device_fields_list = device_inventory.columns
    interface_fields_list = interface_inventory.columns
    interface_template = False
    interface_template_lines = []
    generate_interfaces = False
    config_list = []
    for i,device in target_device_inventory.iterrows():
        generated_config = ''
        for line in config_template:       
            if 'end_interface_template' in line:
                generate_interfaces = True
                interface_template = False
            elif interface_template:
                interface_template_lines.append(line)
            elif 'interfaces:' in line:
                interface_role = line.split('##')[1].split(':')[1]
                interface_template = True
                interface_template_lines = []
            if generate_interfaces:
                
                target_interface_mask = np.ones(interface_inventory.shape[0])
                target_interface_mask = np.logical_and(target_interface_mask,interface_inventory['device_name']==device['device_name'])
                target_interface_mask = np.logical_and(target_interface_mask,interface_inventory['interface_role']==interface_role)
                target_interfaces = interface_inventory[target_interface_mask]
                generated_interface_config = ''
                for j,interf in target_interfaces.iterrows():
                    for template_line in interface_template_lines:
                        line_components = template_line.split('##')
                        generated_config_line = ''
                        for element in line_components:
                            if element in device_fields_list:
                                generated_config_line += str(device[element])
                            elif element in interface_fields_list:
                                generated_config_line += str(interf[element])
                            elif element == 'random':
                                generated_config_line += str(np.random.randint(0,10000))
                            else:
                                generated_config_line += element
                        generated_interface_config +=generated_config_line
                generated_config += generated_interface_config
                generate_interfaces = False
            elif not interface_template:
                line_components = line.split('##')
                generated_config_line = ''
                for element in line_components:
                    if element in device_fields_list:
                        generated_config_line += str(device[element])
                    elif element == 'random':
                        generated_config_line += str(np.random.randint(0,10000))
                    else:
                        generated_config_line += element
                generated_config += generated_config_line
        config_object = dict()
        config_object['device_name']=device['device_name']
        config_object['config']=generated_config
        config_list.append(config_object)
    configs_df = pd.DataFrame(columns=config_object.keys())
    for config_object in config_list:
        configs_df=configs_df.append(config_object,ignore_index=True)
    
    return configs_df






