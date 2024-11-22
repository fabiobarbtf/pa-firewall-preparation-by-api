####################################### START - Importing Libraries #######################################
import requests
import time
from datetime import datetime
import urllib3
import warnings
from panos import base
from panos import firewall
from panos import panorama
from panos import policies
from panos import objects
from panos import network
from panos import device
from panos import plugins
import random
from passlib.hash import sha256_crypt # type: ignore
import string
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings("ignore")
######################################## END - Importing Libraries ########################################

####################################### START - Access Settings #######################################
##### Script Banner #####
print(r"""
 _____   _                                    _   _                           
|  ___| (_)  _ __    ___  __      __   __ _  | | | |                          
| |_    | | | '__|  / _ \ \ \ /\ / /  / _` | | | | |                          
|  _|   | | | |    |  __/  \ V  V /  | (_| | | | | |                          
|_|__   |_| |_|     \___|   \_/\_/    \__,_| |_| |_|  _     _                 
|  _ \   _ __    ___   _ __     __ _   _ __    __ _  | |_  (_)   ___    _ __  
| |_) | | '__|  / _ \ | '_ \   / _` | | '__|  / _` | | __| | |  / _ \  | '_ \ 
|  __/  | |    |  __/ | |_) | | (_| | | |    | (_| | | |_  | | | (_) | | | | |
|_|     |_|     \___| | .__/   \__,_| |_|     \__,_|  \__| |_|  \___/  |_| |_|
                      |_|                                                     
""")
print("")
### Management Interface Input ###
mgmt = input("""Please provide the firewall IP!
Management IP: """)
print('')
### UJser Input ###
user = input("""Inform the login user!
User: """)
print('')
### Password Input ###
password = input("""Enter the login password!
Password: """)
print('')
#### Base Version Input ####
version = str(input("""Inform the firewall base version! Examples:
    11.2, 11.1, 11.0
    10.2, 10.1, 10.0
Base Version: """))
if version == '11.2' or version == '11.1' or version == '11.0' or version == '10.2' or version == '10.1' or version == '10.0':
    print(f"Existing Base Version: {version}")
else:
    print("Base version does not exist! Restart the script!")
    input()
    exit()
print('')
######################################## END - Access Settings ########################################

####################################### START - API Settings #######################################
### API Key Collection ###
print(f"Starting API Key Collection on {mgmt} firewall! Please wait...")
try:
    url = (f'https://{mgmt}/api/?type=keygen&user={user}&password={password}')
except:
    url = (f'https://{mgmt}/api/?type=keygen&user={user}&password={password}')
call_response = requests.get(url, verify=False)
### Response Processing ###
call_content = str(call_response.content)
call_content = call_content.strip('"')
content_strip = call_content[44:]
api_key = content_strip.replace("</key></result></response>", "")
print(f"API Key Collected! API Key: {api_key}")
print("")
### Call Header Configuration ###
headers = {
  'Content-Type': 'application/json',
  'Accept': "application/json",
  "X-PAN-KEY": f"{api_key}"
  }
######################################## END - API Settings ########################################

####################################### START - Creating Main Objects #######################################
fw = firewall.Firewall(mgmt, api_username=user, api_password=password)
password_new = "Not configured!"
profiles_config = "Not Configured!"
choose_delete_rsp = "Not deleted!"
hostname_new = ""
mgmt_new = ""
netmask_new = ""
defaultgateway_new = ""
dnsprimary_new = ""
dnssecondary_new = ""
option = 0
loginbanner_config = "ATTENTION!!! You are about to access a private environment. This access is exclusive to authorized persons who are aware of the Information Security policy. The use of resources is recorded and may be monitored. The information security area may provide evidence of access to the responsible authorities and apply disciplinary measures in the administrative, legal or criminal spheres. The use of information must be exclusively for professional needs, and use for personal interests is prohibited."
timezone_config = "America/Sao_Paulo"
######################################## END - Creating Main Objects ########################################




####################################### START - Security Profile Functions #######################################
### Fileblocking Profile Creation ###
def FileBlocking_Creation():
    ### Outbound-FB Creation ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Objects/FileBlockingSecurityProfiles?location=vsys&vsys=vsys1&name=Outbound-FB')
    data = {
    "entry": {
        "@name": "Outbound-FB",
        "@location": "vsys",
        "@vsys": "vsys1",
        "description": "Best-Practicies Fileblocking Profile",
        "rules": {
        "entry": [
            {
            "@name": "Alert-All",
            "application": {
                "member": [
                "any"
                ]
            },
            "file-type": {
                "member": [
                "any"
                ]
            },
            "direction": "both",
            "action": "alert"
            },
            {
            "@name": "Block",
            "application": {
                "member": [
                "any"
                ]
            },
            "file-type": {
                "member": [
                "7z",
                "bat",
                "chm",
                "class",
                "cpl",
                "dll",
                "hlp",
                "hta",
                "jar",
                "ocx",
                "pif",
                "scr",
                "torrent",
                "vbe",
                "wsf"
                ]
            },
            "direction": "both",
            "action": "block"
            }
        ]
        }
    }
    }
    creation_response = requests.post (url=api_url, headers=headers, json=data, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("Fileblocking Outbound-FB profile not created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The Fileblocking Outbound-FB profile has been successfully created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    ### Inbound-FB Creation ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Objects/FileBlockingSecurityProfiles?location=vsys&vsys=vsys1&name=Inbound-FB')
    data = {
    "entry": {
        "@name": "Inbound-FB",
        "@location": "vsys",
        "@vsys": "vsys1",
        "description": "Best-Practicies Fileblocking Profile",
        "rules": {
        "entry": [
            {
            "@name": "Alert-All",
            "application": {
                "member": [
                "any"
                ]
            },
            "file-type": {
                "member": [
                "any"
                ]
            },
            "direction": "both",
            "action": "alert"
            },
            {
            "@name": "Block",
            "application": {
                "member": [
                "any"
                ]
            },
            "file-type": {
                "member": [
                "7z",
                "bat",
                "chm",
                "class",
                "cpl",
                "dll",
                "hlp",
                "hta",
                "jar",
                "ocx",
                "pif",
                "scr",
                "torrent",
                "vbe",
                "wsf"
                ]
            },
            "direction": "both",
            "action": "block"
            }
        ]
        }
    }
    }
    creation_response = requests.post (url=api_url, headers=headers, json=data, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("Fileblocking Inbound-FB profile not created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The Fileblocking Inbound-FB profile has been successfully created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    ### Internal-FB Creation ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Objects/FileBlockingSecurityProfiles?location=vsys&vsys=vsys1&name=Internal-FB')
    data = {
    "entry": {
        "@name": "Internal-FB",
        "@location": "vsys",
        "@vsys": "vsys1",
        "description": "Best-Practicies Fileblocking Profile",
        "rules": {
        "entry": [
            {
            "@name": "Alert-All",
            "application": {
                "member": [
                "any"
                ]
            },
            "file-type": {
                "member": [
                "any"
                ]
            },
            "direction": "both",
            "action": "alert"
            },
            {
            "@name": "Block",
            "application": {
                "member": [
                "any"
                ]
            },
            "file-type": {
                "member": [
                "7z",
                "bat",
                "chm",
                "class",
                "cpl",
                "dll",
                "hlp",
                "hta",
                "jar",
                "ocx",
                "pif",
                "scr",
                "torrent",
                "vbe",
                "wsf"
                ]
            },
            "direction": "both",
            "action": "block"
            }
        ]
        }
    }
    }
    creation_response = requests.post (url=api_url, headers=headers, json=data, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("The Fileblocking Internal-FB profile was not created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The Fileblocking Internal-FB profile has been successfully created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    ### Alert-Only-FB Creation ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Objects/FileBlockingSecurityProfiles?location=vsys&vsys=vsys1&name=Alert-Only-FB')
    data = {
    "entry": {
        "@name": "Alert-Only-FB",
        "@location": "vsys",
        "@vsys": "vsys1",
        "description": "Best-Practicies Fileblocking Profile",
        "rules": {
        "entry": [
            {
            "@name": "Alert-Only",
            "application": {
                "member": [
                "any"
                ]
            },
            "file-type": {
                "member": [
                "any"
                ]
            },
            "direction": "both",
            "action": "alert"
            }
        ]
        }
    }
    }
    creation_response = requests.post (url=api_url, headers=headers, json=data, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("Fileblocking Alert-Only-FB profile not created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The Fileblocking Alert-Only-FB profile has been successfully created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
### Any-Spyware Profile Creation ###
def AntiSpyware_Creation():
    ### Outbound-AS Creation ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Objects/AntiSpywareSecurityProfiles?location=vsys&vsys=vsys1&name=Outbound-AS')
    data = {
    "entry": {
        "@name": "Outbound-AS",
        "description": "Best-Practicies Antispyware Profile",
        "botnet-domains": {
        "lists": {
            "entry": [
            {
                "@name": "default-paloalto-dns",
                "action": {
                "sinkhole": {}
                },
                "packet-capture": "single-packet"
            }
            ]
        },
        "dns-security-categories": {
            "entry": [
            {
                "@name": "pan-dns-sec-benign",
                "action": "default",
                "log-level": "default",
                "packet-capture": "disable"
            },
            {
                "@name": "pan-dns-sec-cc",
                "action": "sinkhole",
                "log-level": "default",
                "packet-capture": "single-packet"
            },
            {
                "@name": "pan-dns-sec-ddns",
                "action": "default",
                "log-level": "default",
                "packet-capture": "single-packet"
            },
            {
                "@name": "pan-dns-sec-grayware",
                "action": "sinkhole",
                "log-level": "default",
                "packet-capture": "single-packet"
            },
            {
                "@name": "pan-dns-sec-parked",
                "action": "default",
                "log-level": "default",
                "packet-capture": "disable"
            },
            {
                "@name": "pan-dns-sec-phishing",
                "action": "sinkhole",
                "log-level": "default",
                "packet-capture": "single-packet"
            },
            {
                "@name": "pan-dns-sec-proxy",
                "action": "sinkhole",
                "log-level": "default",
                "packet-capture": "single-packet"
            },
            {
                "@name": "pan-dns-sec-malware",
                "action": "sinkhole",
                "log-level": "default",
                "packet-capture": "single-packet"
            },
            {
                "@name": "pan-dns-sec-recent",
                "action": "default",
                "log-level": "default",
                "packet-capture": "single-packet"
            }
            ]
        },
        "sinkhole": {
            "ipv4-address": "sinkhole.paloaltonetworks.com",
            "ipv6-address": "2600:5200::1"
        }
        },
        "rules": {
        "entry": [
            {
            "@name": "Block-Critical-High-Medium",
            "threat-name": "any",
            "category": "any",
            "severity": {
                "member": [
                "high",
                "critical",
                "medium"
                ]
            },
            "action": {
                "reset-both": {}
            },
            "packet-capture": "single-packet"
            },
            {
            "@name": "Default-Low-Info",
            "threat-name": "any",
            "category": "any",
            "severity": {
                "member": [
                "low",
                "informational"
                ]
            },
            "action": {
                "default": {}
            },
            "packet-capture": "disable"
            }
        ]
        },
        "cloud-inline-analysis": "yes",
        "mica-engine-spyware-enabled": {
        "entry": [
            {
            "@name": "HTTP Command and Control detector",
            "inline-policy-action": "reset-both"
            },
            {
            "@name": "HTTP2 Command and Control detector",
            "inline-policy-action": "reset-both"
            },
            {
            "@name": "SSL Command and Control detector",
            "inline-policy-action": "reset-both"
            },
            {
            "@name": "Unknown-TCP Command and Control detector",
            "inline-policy-action": "reset-both"
            },
            {
            "@name": "Unknown-UDP Command and Control detector",
            "inline-policy-action": "reset-both"
            }
        ]
        }
    }
    }
    creation_response = requests.post (url=api_url, headers=headers, json=data, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("The Outbound-AS Anti-Spyware profile was not created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The Outbound-AS Anti-Spyware profile has been successfully created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    ### Inbound-AS Creation ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Objects/AntiSpywareSecurityProfiles?location=vsys&vsys=vsys1&name=Inbound-AS')
    data = {
    "entry": {
        "@name": "Inbound-AS",
        "description": "Best-Practicies Antispyware Profile",
        "botnet-domains": {
        "lists": {
            "entry": [
            {
                "@name": "default-paloalto-dns",
                "action": {
                "sinkhole": {}
                },
                "packet-capture": "single-packet"
            }
            ]
        },
        "dns-security-categories": {
            "entry": [
            {
                "@name": "pan-dns-sec-benign",
                "action": "default",
                "log-level": "default",
                "packet-capture": "disable"
            },
            {
                "@name": "pan-dns-sec-cc",
                "action": "sinkhole",
                "log-level": "default",
                "packet-capture": "single-packet"
            },
            {
                "@name": "pan-dns-sec-ddns",
                "action": "default",
                "log-level": "default",
                "packet-capture": "single-packet"
            },
            {
                "@name": "pan-dns-sec-grayware",
                "action": "sinkhole",
                "log-level": "default",
                "packet-capture": "single-packet"
            },
            {
                "@name": "pan-dns-sec-parked",
                "action": "default",
                "log-level": "default",
                "packet-capture": "disable"
            },
            {
                "@name": "pan-dns-sec-phishing",
                "action": "sinkhole",
                "log-level": "default",
                "packet-capture": "single-packet"
            },
            {
                "@name": "pan-dns-sec-proxy",
                "action": "sinkhole",
                "log-level": "default",
                "packet-capture": "single-packet"
            },
            {
                "@name": "pan-dns-sec-malware",
                "action": "sinkhole",
                "log-level": "default",
                "packet-capture": "single-packet"
            },
            {
                "@name": "pan-dns-sec-recent",
                "action": "default",
                "log-level": "default",
                "packet-capture": "single-packet"
            }
            ]
        },
        "sinkhole": {
            "ipv4-address": "sinkhole.paloaltonetworks.com",
            "ipv6-address": "2600:5200::1"
        }
        },
        "rules": {
        "entry": [
            {
            "@name": "Block-Critical-High-Medium",
            "threat-name": "any",
            "category": "any",
            "severity": {
                "member": [
                "high",
                "critical",
                "medium"
                ]
            },
            "action": {
                "reset-both": {}
            },
            "packet-capture": "single-packet"
            },
            {
            "@name": "Default-Low-Info",
            "threat-name": "any",
            "category": "any",
            "severity": {
                "member": [
                "low",
                "informational"
                ]
            },
            "action": {
                "default": {}
            },
            "packet-capture": "disable"
            }
        ]
        },
        "cloud-inline-analysis": "yes",
        "mica-engine-spyware-enabled": {
        "entry": [
            {
            "@name": "HTTP Command and Control detector",
            "inline-policy-action": "reset-both"
            },
            {
            "@name": "HTTP2 Command and Control detector",
            "inline-policy-action": "reset-both"
            },
            {
            "@name": "SSL Command and Control detector",
            "inline-policy-action": "reset-both"
            },
            {
            "@name": "Unknown-TCP Command and Control detector",
            "inline-policy-action": "reset-both"
            },
            {
            "@name": "Unknown-UDP Command and Control detector",
            "inline-policy-action": "reset-both"
            }
        ]
        }
    }
    }
    creation_response = requests.post (url=api_url, headers=headers, json=data, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("The Inbound-AS Anti-Spyware profile was not created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The Inbound-AS Anti-Spyware profile has been successfully created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    ### Internal-AS Creation ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Objects/AntiSpywareSecurityProfiles?location=vsys&vsys=vsys1&name=Internal-AS')
    data = {
    "entry": {
        "@name": "Internal-AS",
        "description": "Best-Practicies Antispyware Profile",
        "botnet-domains": {
        "lists": {
            "entry": [
            {
                "@name": "default-paloalto-dns",
                "action": {
                "sinkhole": {}
                },
                "packet-capture": "single-packet"
            }
            ]
        },
        "dns-security-categories": {
            "entry": [
            {
                "@name": "pan-dns-sec-benign",
                "action": "default",
                "log-level": "default",
                "packet-capture": "disable"
            },
            {
                "@name": "pan-dns-sec-cc",
                "action": "sinkhole",
                "log-level": "default",
                "packet-capture": "single-packet"
            },
            {
                "@name": "pan-dns-sec-ddns",
                "action": "default",
                "log-level": "default",
                "packet-capture": "single-packet"
            },
            {
                "@name": "pan-dns-sec-grayware",
                "action": "sinkhole",
                "log-level": "default",
                "packet-capture": "single-packet"
            },
            {
                "@name": "pan-dns-sec-parked",
                "action": "default",
                "log-level": "default",
                "packet-capture": "disable"
            },
            {
                "@name": "pan-dns-sec-phishing",
                "action": "sinkhole",
                "log-level": "default",
                "packet-capture": "single-packet"
            },
            {
                "@name": "pan-dns-sec-proxy",
                "action": "sinkhole",
                "log-level": "default",
                "packet-capture": "single-packet"
            },
            {
                "@name": "pan-dns-sec-malware",
                "action": "sinkhole",
                "log-level": "default",
                "packet-capture": "single-packet"
            },
            {
                "@name": "pan-dns-sec-recent",
                "action": "default",
                "log-level": "default",
                "packet-capture": "single-packet"
            }
            ]
        },
        "sinkhole": {
            "ipv4-address": "sinkhole.paloaltonetworks.com",
            "ipv6-address": "2600:5200::1"
        }
        },
        "rules": {
        "entry": [
            {
            "@name": "Block-Critical-High",
            "threat-name": "any",
            "category": "any",
            "severity": {
                "member": [
                "high",
                "critical"
                ]
            },
            "action": {
                "reset-both": {}
            },
            "packet-capture": "single-packet"
            },
            {
            "@name": "Default-Medium-Low-Info",
            "threat-name": "any",
            "category": "any",
            "severity": {
                "member": [
                "low",
                "informational",
                "medium"
                ]
            },
            "action": {
                "default": {}
            },
            "packet-capture": "disable"
            }
        ]
        },
        "cloud-inline-analysis": "yes",
        "mica-engine-spyware-enabled": {
        "entry": [
            {
            "@name": "HTTP Command and Control detector",
            "inline-policy-action": "reset-both"
            },
            {
            "@name": "HTTP2 Command and Control detector",
            "inline-policy-action": "reset-both"
            },
            {
            "@name": "SSL Command and Control detector",
            "inline-policy-action": "reset-both"
            },
            {
            "@name": "Unknown-TCP Command and Control detector",
            "inline-policy-action": "reset-both"
            },
            {
            "@name": "Unknown-UDP Command and Control detector",
            "inline-policy-action": "reset-both"
            }
        ]
        }
    }
    }
    creation_response = requests.post (url=api_url, headers=headers, json=data, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("The Internal-AS Anti-Spyware profile was not created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The Internal-AS Anti-Spyware profile has been successfully created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    ### Alert-Only-AS Creation ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Objects/AntiSpywareSecurityProfiles?location=vsys&vsys=vsys1&name=Alert-Only-AS')
    data = {
    "entry": {
        "@name": "Alert-Only-AS",
        "description": "Best-Practicies Antispyware Profile",
        "botnet-domains": {
        "lists": {
            "entry": [
            {
                "@name": "default-paloalto-dns",
                "action": {
                "alert": {}
                },
                "packet-capture": "disable"
            }
            ]
        },
        "dns-security-categories": {
            "entry": [
            {
                "@name": "pan-dns-sec-benign",
                "action": "allow",
                "log-level": "default",
                "packet-capture": "disable"
            },
            {
                "@name": "pan-dns-sec-cc",
                "action": "allow",
                "log-level": "default",
                "packet-capture": "single-packet"
            },
            {
                "@name": "pan-dns-sec-ddns",
                "action": "allow",
                "log-level": "default",
                "packet-capture": "single-packet"
            },
            {
                "@name": "pan-dns-sec-grayware",
                "action": "allow",
                "log-level": "default",
                "packet-capture": "single-packet"
            },
            {
                "@name": "pan-dns-sec-parked",
                "action": "allow",
                "log-level": "default",
                "packet-capture": "single-packet"
            },
            {
                "@name": "pan-dns-sec-phishing",
                "action": "allow",
                "log-level": "default",
                "packet-capture": "single-packet"
            },
            {
                "@name": "pan-dns-sec-proxy",
                "action": "allow",
                "log-level": "default",
                "packet-capture": "single-packet"
            },
            {
                "@name": "pan-dns-sec-malware",
                "action": "allow",
                "log-level": "default",
                "packet-capture": "single-packet"
            },
            {
                "@name": "pan-dns-sec-recent",
                "action": "allow",
                "log-level": "default",
                "packet-capture": "single-packet"
            }
            ]
        },
        "sinkhole": {
            "ipv4-address": "sinkhole.paloaltonetworks.com",
            "ipv6-address": "2600:5200::1"
        }
        },
        "rules": {
        "entry": [
            {
            "@name": "Alert-All",
            "threat-name": "any",
            "category": "any",
            "severity": {
                "member": [
                "any"
                ]
            },
            "action": {
                "alert": {}
            },
            "packet-capture": "disable"
            }
        ]
        },
        "cloud-inline-analysis": "yes",
        "mica-engine-spyware-enabled": {
        "entry": [
            {
            "@name": "HTTP Command and Control detector",
            "inline-policy-action": "alert"
            },
            {
            "@name": "HTTP2 Command and Control detector",
            "inline-policy-action": "alert"
            },
            {
            "@name": "SSL Command and Control detector",
            "inline-policy-action": "alert"
            },
            {
            "@name": "Unknown-TCP Command and Control detector",
            "inline-policy-action": "alert"
            },
            {
            "@name": "Unknown-UDP Command and Control detector",
            "inline-policy-action": "alert"
            }
        ]
        }
    }
    }
    creation_response = requests.post (url=api_url, headers=headers, json=data, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("The Anti-Spyware Alert-Only-AS profile was not created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The Alert-Only-AS Anti-Spyware profile has been successfully created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
### URL Filtering Profile Creation ###
def UrlFiltering_Creation():
    ### Block Category Creation ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Objects/CustomURLCategories?location=vsys&vsys=vsys1&name=Block')
    data = {
    "entry": {
        "@name": "Block",
        "description": "Block URL List",
        "type": "URL List"
    }
    }
    creation_response = requests.post (url=api_url, headers=headers, json=data, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("Custom URL List Block profile not created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The Custom URL List Block profile has been successfully created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    ### Allow Category Creation ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Objects/CustomURLCategories?location=vsys&vsys=vsys1&name=Allow')
    data = {
    "entry": {
        "@name": "Allow",
        "description": "Allow URL List",
        "type": "URL List"
    }
    }
    creation_response = requests.post (url=api_url, headers=headers, json=data, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("Custom URL List Allow profile not created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The Custom URL List Allow profile has been created successfully! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    ### Custom-No-Decrypt Category Creation ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Objects/CustomURLCategories?location=vsys&vsys=vsys1&name=Custom-No-Decrypt')
    data = {
    "entry": {
        "@name": "Custom-No-Decrypt",
        "description": "Custom No Decrypt URL List",
        "type": "URL List"
    }
    }
    creation_response = requests.post (url=api_url, headers=headers, json=data, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("The Custom URL List Custom-No-Decrypt profile was not created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The Custom URL List Custom-No-Decrypt profile has been successfully created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    ### Outbound-URL Creation ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Objects/URLFilteringSecurityProfiles?location=vsys&vsys=vsys1&name=Outbound-URL')
    data = {
    "entry": {
        "@name": "Outbound-URL",
        "description": "Best-Practicies URL Filtering Profile",
        "alert": {
        "member": [
            "Allow",
            "abortion",
            "abused-drugs",
            "adult",
            "alcohol-and-tobacco",
            "auctions",
            "business-and-economy",
            "computer-and-internet-info",
            "content-delivery-networks",
            "copyright-infringement",
            "cryptocurrency",
            "dating",
            "dynamic-dns",
            "educational-institutions",
            "entertainment-and-arts",
            "extremism",
            "financial-services",
            "gambling",
            "games",
            "government",
            "hacking",
            "health-and-medicine",
            "high-risk",
            "home-and-garden",
            "hunting-and-fishing",
            "insufficient-content",
            "internet-communications-and-telephony",
            "internet-portals",
            "job-search",
            "legal",
            "low-risk",
            "medium-risk",
            "military",
            "motor-vehicles",
            "music",
            "newly-registered-domain",
            "news",
            "not-resolved",
            "nudity",
            "online-storage-and-backup",
            "parked",
            "peer-to-peer",
            "personal-sites-and-blogs",
            "philosophy-and-political-advocacy",
            "private-ip-addresses",
            "proxy-avoidance-and-anonymizers",
            "questionable",
            "real-estate",
            "recreation-and-hobbies",
            "reference-and-research",
            "religion",
            "search-engines",
            "sex-education",
            "shareware-and-freeware",
            "shopping",
            "social-networking",
            "society",
            "sports",
            "stock-advice-and-tools",
            "streaming-media",
            "swimsuits-and-intimate-apparel",
            "training-and-tools",
            "translation",
            "travel",
            "unknown",
            "weapons",
            "web-advertisements",
            "web-based-email",
            "web-hosting"
        ]
        },
        "block": {
        "member": [
            "Block",
            "command-and-control",
            "grayware",
            "malware",
            "phishing",
            "ransomware"
        ]
        },
        "credential-enforcement": {
        "mode": {
            "ip-user": {}
        },
        "log-severity": "high",
        "alert": {
            "member": [
            "real-time-detection"
            ]
        },
        "block": {
            "member": [
            "Block",
            "Allow",
            "abortion",
            "abused-drugs",
            "adult",
            "alcohol-and-tobacco",
            "auctions",
            "business-and-economy",
            "command-and-control",
            "computer-and-internet-info",
            "content-delivery-networks",
            "copyright-infringement",
            "cryptocurrency",
            "dating",
            "dynamic-dns",
            "educational-institutions",
            "entertainment-and-arts",
            "extremism",
            "financial-services",
            "gambling",
            "games",
            "government",
            "grayware",
            "hacking",
            "health-and-medicine",
            "high-risk",
            "home-and-garden",
            "hunting-and-fishing",
            "insufficient-content",
            "internet-communications-and-telephony",
            "internet-portals",
            "job-search",
            "legal",
            "low-risk",
            "malware",
            "medium-risk",
            "military",
            "motor-vehicles",
            "music",
            "newly-registered-domain",
            "news",
            "not-resolved",
            "nudity",
            "online-storage-and-backup",
            "parked",
            "peer-to-peer",
            "personal-sites-and-blogs",
            "philosophy-and-political-advocacy",
            "phishing",
            "private-ip-addresses",
            "proxy-avoidance-and-anonymizers",
            "questionable",
            "ransomware",
            "real-estate",
            "recreation-and-hobbies",
            "reference-and-research",
            "religion",
            "search-engines",
            "sex-education",
            "shareware-and-freeware",
            "shopping",
            "social-networking",
            "society",
            "sports",
            "stock-advice-and-tools",
            "streaming-media",
            "swimsuits-and-intimate-apparel",
            "training-and-tools",
            "translation",
            "travel",
            "unknown",
            "weapons",
            "web-advertisements",
            "web-based-email",
            "web-hosting"
            ]
        }
        },
        "log-http-hdr-xff": "yes",
        "log-http-hdr-user-agent": "yes",
        "log-http-hdr-referer": "yes",
        "local-inline-cat": "yes",
        "cloud-inline-cat": "yes",
    }
    }
    creation_response = requests.post (url=api_url, headers=headers, json=data, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("The URL Filtering Outbound-URL profile was not created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The URL Filtering Outbound-URL profile has been successfully created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    ### Alert-Only-URL Creation ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Objects/URLFilteringSecurityProfiles?location=vsys&vsys=vsys1&name=Alert-Only-URL')
    data = {
    "entry": {
        "@name": "Alert-Only-URL",
        "description": "Best-Practicies URL Filtering Profile",
        "alert": {
        "member": [
            "Block",
            "Allow",
            "abortion",
            "abused-drugs",
            "adult",
            "alcohol-and-tobacco",
            "auctions",
            "business-and-economy",
            "command-and-control",
            "computer-and-internet-info",
            "content-delivery-networks",
            "copyright-infringement",
            "cryptocurrency",
            "dating",
            "dynamic-dns",
            "educational-institutions",
            "entertainment-and-arts",
            "extremism",
            "financial-services",
            "gambling",
            "games",
            "government",
            "grayware",
            "hacking",
            "health-and-medicine",
            "high-risk",
            "home-and-garden",
            "hunting-and-fishing",
            "insufficient-content",
            "internet-communications-and-telephony",
            "internet-portals",
            "job-search",
            "legal",
            "low-risk",
            "malware",
            "medium-risk",
            "military",
            "motor-vehicles",
            "music",
            "newly-registered-domain",
            "news",
            "not-resolved",
            "nudity",
            "online-storage-and-backup",
            "parked",
            "peer-to-peer",
            "personal-sites-and-blogs",
            "philosophy-and-political-advocacy",
            "phishing",
            "private-ip-addresses",
            "proxy-avoidance-and-anonymizers",
            "questionable",
            "ransomware",
            "real-estate",
            "recreation-and-hobbies",
            "reference-and-research",
            "religion",
            "search-engines",
            "sex-education",
            "shareware-and-freeware",
            "shopping",
            "social-networking",
            "society",
            "sports",
            "stock-advice-and-tools",
            "streaming-media",
            "swimsuits-and-intimate-apparel",
            "training-and-tools",
            "translation",
            "travel",
            "unknown",
            "weapons",
            "web-advertisements",
            "web-based-email",
            "web-hosting"
        ]
        },
        "credential-enforcement": {
        "mode": {
            "ip-user": {}
        },
        "log-severity": "medium",
        "alert": {
            "member": [
            "Block",
            "Allow",
            "abortion",
            "abused-drugs",
            "adult",
            "alcohol-and-tobacco",
            "auctions",
            "business-and-economy",
            "command-and-control",
            "computer-and-internet-info",
            "content-delivery-networks",
            "copyright-infringement",
            "cryptocurrency",
            "dating",
            "dynamic-dns",
            "educational-institutions",
            "entertainment-and-arts",
            "extremism",
            "financial-services",
            "gambling",
            "games",
            "government",
            "grayware",
            "hacking",
            "health-and-medicine",
            "high-risk",
            "home-and-garden",
            "hunting-and-fishing",
            "insufficient-content",
            "internet-communications-and-telephony",
            "internet-portals",
            "job-search",
            "legal",
            "low-risk",
            "malware",
            "medium-risk",
            "military",
            "motor-vehicles",
            "music",
            "newly-registered-domain",
            "news",
            "not-resolved",
            "nudity",
            "online-storage-and-backup",
            "parked",
            "peer-to-peer",
            "personal-sites-and-blogs",
            "philosophy-and-political-advocacy",
            "phishing",
            "private-ip-addresses",
            "proxy-avoidance-and-anonymizers",
            "questionable",
            "ransomware",
            "real-estate",
            "recreation-and-hobbies",
            "reference-and-research",
            "religion",
            "search-engines",
            "sex-education",
            "shareware-and-freeware",
            "shopping",
            "social-networking",
            "society",
            "sports",
            "stock-advice-and-tools",
            "streaming-media",
            "swimsuits-and-intimate-apparel",
            "training-and-tools",
            "translation",
            "travel",
            "unknown",
            "weapons",
            "web-advertisements",
            "web-based-email",
            "web-hosting"
            ]
        }
        },
        "log-http-hdr-xff": "yes",
        "log-http-hdr-user-agent": "yes",
        "log-http-hdr-referer": "yes",
        "local-inline-cat": "yes",
        "cloud-inline-cat": "yes",
    }
    }
    creation_response = requests.post (url=api_url, headers=headers, json=data, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("The URL Filtering Alert-Only-URL profile was not created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The URL Filtering Alert-Only-URL profile has been successfully created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
### AntiVirus Profile Creation ###
def AntiVirus_Creation():
    ### Alert-Only-AV Creation ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Objects/AntivirusSecurityProfiles?location=vsys&vsys=vsys1&name=Alert-Only-AV')
    data = {
    "entry": {
        "@name": "Alert-Only-AV",
        "description": "Best-Practicies Antivirus Profile",
        "mlav-engine-filebased-enabled": {
        "entry": [
            {
            "@name": "Windows Executables",
            "mlav-policy-action": "enable(alert-only)"
            },
            {
            "@name": "PowerShell Script 1",
            "mlav-policy-action": "enable(alert-only)"
            },
            {
            "@name": "PowerShell Script 2",
            "mlav-policy-action": "enable(alert-only)"
            },
            {
            "@name": "Executable Linked Format",
            "mlav-policy-action": "enable(alert-only)"
            },
            {
            "@name": "MSOffice",
            "mlav-policy-action": "enable(alert-only)"
            },
            {
            "@name": "Shell",
            "mlav-policy-action": "enable(alert-only)"
            }
        ]
        },
        "decoder": {
        "entry": [
            {
            "@name": "ftp",
            "action": "alert",
            "wildfire-action": "alert",
            "mlav-action": "alert"
            },
            {
            "@name": "http",
            "action": "alert",
            "wildfire-action": "alert",
            "mlav-action": "alert"
            },
            {
            "@name": "http2",
            "action": "alert",
            "wildfire-action": "alert",
            "mlav-action": "alert"
            },
            {
            "@name": "imap",
            "action": "alert",
            "wildfire-action": "alert",
            "mlav-action": "alert"
            },
            {
            "@name": "pop3",
            "action": "alert",
            "wildfire-action": "alert",
            "mlav-action": "alert"
            },
            {
            "@name": "smb",
            "action": "alert",
            "wildfire-action": "alert",
            "mlav-action": "alert"
            },
            {
            "@name": "smtp",
            "action": "alert",
            "wildfire-action": "alert",
            "mlav-action": "alert"
            }
        ]
        }
    }
    }
    creation_response = requests.post (url=api_url, headers=headers, json=data, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("The Alert-Only-AV Antivirus profile was not created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The Alert-Only-AV Antivirus profile has been successfully created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    ### Outbound-AV Creation ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Objects/AntivirusSecurityProfiles?location=vsys&vsys=vsys1&name=Outbound-AV')
    data = {
    "entry": {
        "@name": "Outbound-AV",
        "description": "Best-Practicies Antivirus Profile",
        "mlav-engine-filebased-enabled": {
        "entry": [
            {
            "@name": "Windows Executables",
            "mlav-policy-action": "enable"
            },
            {
            "@name": "PowerShell Script 1",
            "mlav-policy-action": "enable"
            },
            {
            "@name": "PowerShell Script 2",
            "mlav-policy-action": "enable"
            },
            {
            "@name": "Executable Linked Format",
            "mlav-policy-action": "enable"
            },
            {
            "@name": "MSOffice",
            "mlav-policy-action": "enable"
            },
            {
            "@name": "Shell",
            "mlav-policy-action": "enable"
            }
        ]
        },
        "decoder": {
        "entry": [
            {
            "@name": "ftp",
            "action": "reset-both",
            "wildfire-action": "reset-both",
            "mlav-action": "reset-both"
            },
            {
            "@name": "http",
            "action": "reset-both",
            "wildfire-action": "reset-both",
            "mlav-action": "reset-both"
            },
            {
            "@name": "http2",
            "action": "reset-both",
            "wildfire-action": "reset-both",
            "mlav-action": "reset-both"
            },
            {
            "@name": "imap",
            "action": "reset-both",
            "wildfire-action": "reset-both",
            "mlav-action": "reset-both"
            },
            {
            "@name": "pop3",
            "action": "reset-both",
            "wildfire-action": "reset-both",
            "mlav-action": "reset-both"
            },
            {
            "@name": "smb",
            "action": "reset-both",
            "wildfire-action": "reset-both",
            "mlav-action": "reset-both"
            },
            {
            "@name": "smtp",
            "action": "reset-both",
            "wildfire-action": "reset-both",
            "mlav-action": "reset-both"
            }
        ]
        }
    }
    }
    creation_response = requests.post (url=api_url, headers=headers, json=data, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("Outbound-AV Antivirus profile not created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The Outbound-AV Antivirus profile has been successfully created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    ### Inbound-AV Creation ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Objects/AntivirusSecurityProfiles?location=vsys&vsys=vsys1&name=Inbound-AV')
    data = {
    "entry": {
        "@name": "Inbound-AV",
        "description": "Best-Practicies Antivirus Profile",
        "mlav-engine-filebased-enabled": {
        "entry": [
            {
            "@name": "Windows Executables",
            "mlav-policy-action": "enable"
            },
            {
            "@name": "PowerShell Script 1",
            "mlav-policy-action": "enable"
            },
            {
            "@name": "PowerShell Script 2",
            "mlav-policy-action": "enable"
            },
            {
            "@name": "Executable Linked Format",
            "mlav-policy-action": "enable"
            },
            {
            "@name": "MSOffice",
            "mlav-policy-action": "enable"
            },
            {
            "@name": "Shell",
            "mlav-policy-action": "enable"
            }
        ]
        },
        "decoder": {
        "entry": [
            {
            "@name": "ftp",
            "action": "reset-both",
            "wildfire-action": "reset-both",
            "mlav-action": "reset-both"
            },
            {
            "@name": "http",
            "action": "reset-both",
            "wildfire-action": "reset-both",
            "mlav-action": "reset-both"
            },
            {
            "@name": "http2",
            "action": "reset-both",
            "wildfire-action": "reset-both",
            "mlav-action": "reset-both"
            },
            {
            "@name": "imap",
            "action": "reset-both",
            "wildfire-action": "reset-both",
            "mlav-action": "reset-both"
            },
            {
            "@name": "pop3",
            "action": "reset-both",
            "wildfire-action": "reset-both",
            "mlav-action": "reset-both"
            },
            {
            "@name": "smb",
            "action": "reset-both",
            "wildfire-action": "reset-both",
            "mlav-action": "reset-both"
            },
            {
            "@name": "smtp",
            "action": "reset-both",
            "wildfire-action": "reset-both",
            "mlav-action": "reset-both"
            }
        ]
        }
    }
    }
    creation_response = requests.post (url=api_url, headers=headers, json=data, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("Inbound-AV Antivirus profile not created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The Inbound-AV Antivirus profile has been successfully created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    ### Internal-AV Creation ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Objects/AntivirusSecurityProfiles?location=vsys&vsys=vsys1&name=Internal-AV')
    data = {
    "entry": {
        "@name": "Internal-AV",
        "description": "Best-Practicies Antivirus Profile",
        "mlav-engine-filebased-enabled": {
        "entry": [
            {
            "@name": "Windows Executables",
            "mlav-policy-action": "enable"
            },
            {
            "@name": "PowerShell Script 1",
            "mlav-policy-action": "enable"
            },
            {
            "@name": "PowerShell Script 2",
            "mlav-policy-action": "enable"
            },
            {
            "@name": "Executable Linked Format",
            "mlav-policy-action": "enable"
            },
            {
            "@name": "MSOffice",
            "mlav-policy-action": "enable"
            },
            {
            "@name": "Shell",
            "mlav-policy-action": "enable"
            }
        ]
        },
        "decoder": {
        "entry": [
            {
            "@name": "ftp",
            "action": "reset-both",
            "wildfire-action": "reset-both",
            "mlav-action": "reset-both"
            },
            {
            "@name": "http",
            "action": "reset-both",
            "wildfire-action": "reset-both",
            "mlav-action": "reset-both"
            },
            {
            "@name": "http2",
            "action": "reset-both",
            "wildfire-action": "reset-both",
            "mlav-action": "reset-both"
            },
            {
            "@name": "imap",
            "action": "reset-both",
            "wildfire-action": "reset-both",
            "mlav-action": "reset-both"
            },
            {
            "@name": "pop3",
            "action": "reset-both",
            "wildfire-action": "reset-both",
            "mlav-action": "reset-both"
            },
            {
            "@name": "smb",
            "action": "reset-both",
            "wildfire-action": "reset-both",
            "mlav-action": "reset-both"
            },
            {
            "@name": "smtp",
            "action": "reset-both",
            "wildfire-action": "reset-both",
            "mlav-action": "reset-both"
            }
        ]
        }
    }
    }
    creation_response = requests.post (url=api_url, headers=headers, json=data, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("Internal-AV Antivirus profile not created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The Internal-AV Antivirus profile has been successfully created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
### VulnerabilityProtection Profile Creation ###
def VulnerabilityProtection_Creation():
    ### Outbound-VP Creation ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Objects/VulnerabilityProtectionSecurityProfiles?location=vsys&vsys=vsys1&name=Outbound-VP')
    data = {
    "entry": {
        "@name": "Outbound-VP",
        "description": "Best-Practicies VulnerabilityProtection Profile",
        "rules": {
        "entry": [
            {
            "@name": "Block-Critical-High-Medium",
            "threat-name": "any",
            "cve": {
                "member": [
                "any"
                ]
            },
            "host": "any",
            "vendor-id": {
                "member": [
                "any"
                ]
            },
            "severity": {
                "member": [
                "critical",
                "high",
                "medium"
                ]
            },
            "category": "any",
            "action": {
                "reset-both": {}
            },
            "packet-capture": "single-packet"
            },
            {
            "@name": "Default-Low-Info",
            "threat-name": "any",
            "cve": {
                "member": [
                "any"
                ]
            },
            "host": "any",
            "vendor-id": {
                "member": [
                "any"
                ]
            },
            "severity": {
                "member": [
                "low",
                "informational"
                ]
            },
            "category": "any",
            "action": {
                "default": {}
            },
            "packet-capture": "disable"
            }
        ]
        }
    }
    }
    creation_response = requests.post (url=api_url, headers=headers, json=data, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("The VulnerabilityProtection Outbound-VP profile was not created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The VulnerabilityProtection Outbound-VP profile has been successfully created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    ### Inbound-VP Creation ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Objects/VulnerabilityProtectionSecurityProfiles?location=vsys&vsys=vsys1&name=Inbound-VP')
    data = {
    "entry": {
        "@name": "Inbound-VP",
        "description": "Best-Practicies VulnerabilityProtection Profile",
        "rules": {
        "entry": [
            {
            "@name": "Block-Critical-High-Medium",
            "threat-name": "any",
            "cve": {
                "member": [
                "any"
                ]
            },
            "host": "any",
            "vendor-id": {
                "member": [
                "any"
                ]
            },
            "severity": {
                "member": [
                "critical",
                "high",
                "medium"
                ]
            },
            "category": "any",
            "action": {
                "reset-both": {}
            },
            "packet-capture": "single-packet"
            },
            {
            "@name": "Default-Low-Info",
            "threat-name": "any",
            "cve": {
                "member": [
                "any"
                ]
            },
            "host": "any",
            "vendor-id": {
                "member": [
                "any"
                ]
            },
            "severity": {
                "member": [
                "low",
                "informational"
                ]
            },
            "category": "any",
            "action": {
                "default": {}
            },
            "packet-capture": "disable"
            }
        ]
        }
    }
    }
    creation_response = requests.post (url=api_url, headers=headers, json=data, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("The VulnerabilityProtection Inbound-VP profile was not created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The VulnerabilityProtection Inbound-VP profile has been successfully created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    ### Internal-VP Creation ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Objects/VulnerabilityProtectionSecurityProfiles?location=vsys&vsys=vsys1&name=Internal-VP')
    data = {
    "entry": {
        "@name": "Internal-VP",
        "description": "Best-Practicies VulnerabilityProtection Profile",
        "rules": {
        "entry": [
            {
            "@name": "Block-Critical-High",
            "threat-name": "any",
            "cve": {
                "member": [
                "any"
                ]
            },
            "host": "any",
            "vendor-id": {
                "member": [
                "any"
                ]
            },
            "severity": {
                "member": [
                "critical",
                "high"
                ]
            },
            "category": "any",
            "action": {
                "reset-both": {}
            },
            "packet-capture": "single-packet"
            },
            {
            "@name": "Default-Medium-Low-Info",
            "threat-name": "any",
            "cve": {
                "member": [
                "any"
                ]
            },
            "host": "any",
            "vendor-id": {
                "member": [
                "any"
                ]
            },
            "severity": {
                "member": [
                "low",
                "informational",
                "medium"
                ]
            },
            "category": "any",
            "action": {
                "default": {}
            },
            "packet-capture": "disable"
            }
        ]
        }
    }
    }
    creation_response = requests.post (url=api_url, headers=headers, json=data, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("The VulnerabilityProtection Internal-VP profile was not created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The VulnerabilityProtection Internal-VP profile has been successfully created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    ### Alert-Only-VP Creation ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Objects/VulnerabilityProtectionSecurityProfiles?location=vsys&vsys=vsys1&name=Alert-Only-VP')
    data = {
    "entry": {
        "@name": "Alert-Only-VP",
        "description": "Best-Practicies VulnerabilityProtection Profile",
        "rules": {
        "entry": [
            {
            "@name": "Alert-All",
            "threat-name": "any",
            "cve": {
                "member": [
                "any"
                ]
            },
            "host": "any",
            "vendor-id": {
                "member": [
                "any"
                ]
            },
            "severity": {
                "member": [
                "any",
                ]
            },
            "category": "any",
            "action": {
                "alert": {}
            },
            "packet-capture": "disable"
            }
        ]
        }
    }
    }
    creation_response = requests.post (url=api_url, headers=headers, json=data, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("VulnerabilityProtection Alert-Only-VP profile not created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The VulnerabilityProtection Alert-Only-VP profile has been successfully created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
### WildfireAnalysis Profile Creation ###
def WildfireAnalysis_Creation():
    ### Outbound-WF Creation ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Objects/WildFireAnalysisSecurityProfiles?location=vsys&vsys=vsys1&name=Outbound-WF')
    data = {
    "entry": {
        "@name": "Outbound-WF",
        "description": "Best-Practicies WildfireAnalysis Profile",
        "rules": {
        "entry": [
            {
            "@name": "Forward-All",
            "application": {
                "member": [
                "any"
                ]
            },
            "file-type": {
                "member": [
                "any"
                ]
            },
            "direction": "both",
            "analysis": "public-cloud"
            }
        ]
        }
    }
    }
    creation_response = requests.post (url=api_url, headers=headers, json=data, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("WildfireAnalysis Outbound-WF profile not created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The WildfireAnalysis Outbound-WF profile has been successfully created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    ### Inbound-WF Creation ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Objects/WildFireAnalysisSecurityProfiles?location=vsys&vsys=vsys1&name=Inbound-WF')
    data = {
    "entry": {
        "@name": "Inbound-WF",
        "description": "Best-Practicies WildfireAnalysis Profile",
        "rules": {
        "entry": [
            {
            "@name": "Forward-All",
            "application": {
                "member": [
                "any"
                ]
            },
            "file-type": {
                "member": [
                "any"
                ]
            },
            "direction": "both",
            "analysis": "public-cloud"
            }
        ]
        }
    }
    }
    creation_response = requests.post (url=api_url, headers=headers, json=data, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("WildfireAnalysis Inbound-WF profile not created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The WildfireAnalysis Inbound-WF profile has been successfully created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    ### Internal-WF Creation ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Objects/WildFireAnalysisSecurityProfiles?location=vsys&vsys=vsys1&name=Internal-WF')
    data = {
    "entry": {
        "@name": "Internal-WF",
        "description": "Best-Practicies WildfireAnalysis Profile",
        "rules": {
        "entry": [
            {
            "@name": "Forward-All",
            "application": {
                "member": [
                "any"
                ]
            },
            "file-type": {
                "member": [
                "any"
                ]
            },
            "direction": "both",
            "analysis": "public-cloud"
            }
        ]
        }
    }
    }
    creation_response = requests.post (url=api_url, headers=headers, json=data, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("The WildfireAnalysis Internal-WF profile was not created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The WildfireAnalysis Internal-WF profile has been successfully created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    ### Alert-Only-WF Creation ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Objects/WildFireAnalysisSecurityProfiles?location=vsys&vsys=vsys1&name=Alert-Only-WF')
    data = {
    "entry": {
        "@name": "Alert-Only-WF",
        "description": "Best-Practicies WildfireAnalysis Profile",
        "rules": {
        "entry": [
            {
            "@name": "Forward-All",
            "application": {
                "member": [
                "any"
                ]
            },
            "file-type": {
                "member": [
                "any"
                ]
            },
            "direction": "both",
            "analysis": "public-cloud"
            }
        ]
        }
    }
    }
    creation_response = requests.post (url=api_url, headers=headers, json=data, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("The WildfireAnalysis Alert-Only-WF profile was not created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The WildfireAnalysis Alert-Only-WF profile has been successfully created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
### SecurityProfileGroups Profile Creation ###
def SecurityProfileGroups_Creation():
    ### Outbound Creation ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Objects/SecurityProfileGroups?location=vsys&vsys=vsys1&name=Outbound')
    data = {
    "entry": {
        "@name": "Outbound",
        "virus": {
        "member": [
            "Outbound-AV"
        ]
        },
        "spyware": {
        "member": [
            "Outbound-AS"
        ]
        },
        "vulnerability": {
        "member": [
            "Outbound-VP"
        ]
        },
        "url-filtering": {
        "member": [
            "Outbound-URL"
        ]
        },
        "file-blocking": {
        "member": [
            "Outbound-FB"
        ]
        },
        "wildfire-analysis": {
        "member": [
            "Outbound-WF"
        ]
        }
    }
    }
    creation_response = requests.post (url=api_url, headers=headers, json=data, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("SecurityProfileGroup Outbound was not created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The Outbound SecurityProfileGroup has been successfully created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    ### Inbound Creation ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Objects/SecurityProfileGroups?location=vsys&vsys=vsys1&name=Inbound')
    data = {
    "entry": {
        "@name": "Inbound",
        "virus": {
        "member": [
            "Inbound-AV"
        ]
        },
        "spyware": {
        "member": [
            "Inbound-AS"
        ]
        },
        "vulnerability": {
        "member": [
            "Inbound-VP"
        ]
        },
        "file-blocking": {
        "member": [
            "Inbound-FB"
        ]
        },
        "wildfire-analysis": {
        "member": [
            "Inbound-WF"
        ]
        }
    }
    }
    creation_response = requests.post (url=api_url, headers=headers, json=data, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("The Inbound SecurityProfileGroup was not created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The Inbound SecurityProfileGroup has been successfully created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    ### Internal Creation ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Objects/SecurityProfileGroups?location=vsys&vsys=vsys1&name=Internal')
    data = {
    "entry": {
        "@name": "Internal",
        "virus": {
        "member": [
            "Internal-AV"
        ]
        },
        "spyware": {
        "member": [
            "Internal-AS"
        ]
        },
        "vulnerability": {
        "member": [
            "Internal-VP"
        ]
        },
        "file-blocking": {
        "member": [
            "Internal-FB"
        ]
        },
        "wildfire-analysis": {
        "member": [
            "Internal-WF"
        ]
        }
    }
    }
    creation_response = requests.post (url=api_url, headers=headers, json=data, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("The SecurityProfileGroup Internal was not created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The Internal SecurityProfileGroup has been successfully created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    ### Alert-Only Creation ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Objects/SecurityProfileGroups?location=vsys&vsys=vsys1&name=Alert-Only')
    data = {
    "entry": {
        "@name": "Alert-Only",
        "virus": {
        "member": [
            "Alert-Only-AV"
        ]
        },
        "spyware": {
        "member": [
            "Alert-Only-AS"
        ]
        },
        "vulnerability": {
        "member": [
            "Alert-Only-VP"
        ]
        },
        "url-filtering": {
        "member": [
            "Alert-Only-URL"
        ]
        },
        "file-blocking": {
        "member": [
            "Alert-Only-FB"
        ]
        },
        "wildfire-analysis": {
        "member": [
            "Alert-Only-WF"
        ]
        }
    }
    }
    creation_response = requests.post (url=api_url, headers=headers, json=data, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("The Alert-Only SecurityProfileGroup was not created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The SecurityProfileGroup Alert-Only has been successfully created! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    ### Default Alteration ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Objects/SecurityProfileGroups?location=vsys&vsys=vsys1&name=default')
    data = {
    "entry": {
        "@name": "default",
        "virus": {
        "member": [
            "Outbound-AV"
        ]
        },
        "spyware": {
        "member": [
            "Outbound-AS"
        ]
        },
        "vulnerability": {
        "member": [
            "Outbound-VP"
        ]
        },
        "url-filtering": {
        "member": [
            "Outbound-URL"
        ]
        },
        "file-blocking": {
        "member": [
            "Outbound-FB"
        ]
        },
        "wildfire-analysis": {
        "member": [
            "Outbound-WF"
        ]
        }
    }
    }
    creation_response = requests.post (url=api_url, headers=headers, json=data, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("The default SecurityProfileGroup has not been changed! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The default SecurityProfileGroup has been changed successfully! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
######################################## END - Security Profile Functions ########################################

####################################### START - Defaults Delete Functions #######################################
### Defualt Rule Delete ###
def DeleteDefaultRule():
    ### Defualt Rule Delete ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Policies/SecurityRules?location=vsys&vsys=vsys1&name=rule1')
    creation_response = requests.delete (url=api_url, headers=headers, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("The default object rule1 was not deleted, please check! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The default object rule1 has been deleted successfully! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
### Defualt Interface Delete ###
def DeleteDefaultInterface():
    ### Defualt Interface 1/1 Delete ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Network/EthernetInterfaces?name=ethernet1/1')
    creation_response = requests.delete (url=api_url, headers=headers, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("The default object ethernet1/1 was not deleted, please check! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The default object ethernet1/1 has been deleted successfully! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    ### Defualt Interface 1/2 Delete ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Network/EthernetInterfaces?name=ethernet1/2')
    creation_response = requests.delete (url=api_url, headers=headers, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("The default object ethernet1/2 was not deleted, please check! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The default object ethernet1/2 has been deleted successfully! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')   
### Defualt VirtualRouter Delete ###
def DeleteDefaultVirtualRouter():
    ### Defualt Virtual Router default Delete ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Network/VirtualRouters?name=default')
    creation_response = requests.delete (url=api_url, headers=headers, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("The default VirtualRouter object has not been deleted, please check! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The default VirtualRouter object has been deleted successfully! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
### Defualt VirtualWire Delete ###
def DeleteDefaultVirtualWire():
    ### Defualt Virtual Wire Delete ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Network/VirtualWires?name=default-vwire')
    creation_response = requests.delete (url=api_url, headers=headers, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("The default VirtualWire Object has not been deleted, please check! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The default VVirtualWire object has been deleted successfully! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
### Defualt Zone Delete ###
def DeleteDefaultZone():
    ### Defualt Trust Zone Delete ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Network/Zones?location=vsys&vsys=vsys1&name=trust')
    creation_response = requests.delete (url=api_url, headers=headers, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("The default Zone trust object has not been deleted, please check! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The default Zone trust object has been deleted successfully! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    ### Defualt Untrust Zone Delete ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Network/Zones?location=vsys&vsys=vsys1&name=untrust')
    creation_response = requests.delete (url=api_url, headers=headers, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("The default Zone untrust object has not been deleted, please check! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The default Zone untrust object has been successfully deleted! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
### Defualt QoSProfile Delete ###
def DeleteDefaultQoSProfile():
    ### Defualt QoSProfile Delete ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Network/QoSNetworkProfiles?name=default')
    creation_response = requests.delete (url=api_url, headers=headers, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("The default QoSProfile object default has not been deleted, please check! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The default QoSProfile object default has been deleted successfully! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
### Defualt TunnelMonitor Delete ###
def DeleteDefaultTunnelMonitor():
    ### Defualt Tunnel Monitor Delete ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Network/TunnelMonitorNetworkProfiles?name=default')
    creation_response = requests.delete (url=api_url, headers=headers, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("The default TunnelMonitor object has not been deleted, please check! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The default TunnelMonitor object has been deleted successfully! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
### Defualt IKECrypto Delete ###
def DeleteDefaultIKECrypto():
    ### Defualt IKECryptoProfile default Delete ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Network/IKECryptoNetworkProfiles?name=default')
    creation_response = requests.delete (url=api_url, headers=headers, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("The default IKECrypto Object default has not been deleted, please check! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The IKECrypto default object has been successfully deleted! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    ### Defualt IKECryptoProfile Suite-B-GCM-128 Delete ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Network/IKECryptoNetworkProfiles?name=Suite-B-GCM-128')
    creation_response = requests.delete (url=api_url, headers=headers, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("The IKECrypto Suite-B-GCM-128 Standard Object was not deleted, please check! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The default object IKECrypto Suite-B-GCM-128 has been successfully deleted! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    ### Defualt IKECryptoProfile Suite-B-GCM-256 Delete ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Network/IKECryptoNetworkProfiles?name=Suite-B-GCM-256')
    creation_response = requests.delete (url=api_url, headers=headers, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("The IKECrypto Suite-B-GCM-256 Standard Object was not deleted, please check! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The default object IKECrypto Suite-B-GCM-256 has been successfully deleted! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
### Defualt IPSecCrypto Delete ###
def DeleteDefaultIPSecCrypto():
    ### Defualt IPSecCryptoProfile default Delete ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Network/IPSecCryptoNetworkProfiles?name=default')
    creation_response = requests.delete (url=api_url, headers=headers, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("The default IPSecCrypto Object has not been deleted, please check! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The default IPSecCrypto object default has been deleted successfully! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    ### Defualt IPSecCryptoProfile Suite-B-GCM-128 Delete ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Network/IPSecCryptoNetworkProfiles?name=Suite-B-GCM-128')
    creation_response = requests.delete (url=api_url, headers=headers, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("The IPSecCrypto Suite-B-GCM-128 Default Object was not deleted, please check! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The default object IPSecCrypto Suite-B-GCM-128 has been successfully deleted! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    ### Defualt IPSecCryptoProfile Suite-B-GCM-256 Delete ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Network/IPSecCryptoNetworkProfiles?name=Suite-B-GCM-256')
    creation_response = requests.delete (url=api_url, headers=headers, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("The IPSecCrypto Suite-B-GCM-256 Default Object was not deleted, please check! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The default object IPSecCrypto Suite-B-GCM-256 has been successfully deleted! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
### Defualt GPIPSecCrypto Delete ###
def GPIPSecCryptoProfile():
    ### Defualt GPIPSecCryptoProfile Delete ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Network/GlobalProtectIPSecCryptoNetworkProfiles?name=default')
    creation_response = requests.delete (url=api_url, headers=headers, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("The default GPIPSecCryptoProfile object has not been deleted, please check! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("The default GPIPSecCryptoProfile object has been successfully deleted! Continuing...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
######################################## END - Defaults Delete Functions ########################################

####################################### START - Admin Password Function #######################################
### Admin Password Config ###
def AdminPassword_Config(password_newfunc):
    system_config_password = device.Administrator(name="admin", password_hash=password_newfunc)
    fw.add(system_config_password)
    system_config_password.create()
    print('---------------------------------------------------------------------')
    print(f"PHASH password {password_newfunc} has been set successfully!")
    print('---------------------------------------------------------------------')
    time.sleep(2)
####################################### END - Admin Password Function ########################################

####################################### START - Device Config Functions #######################################
### Login Banner and Timezone ###
def Setup_Timezone_Banner():
    system_config = device.SystemSettings(timezone=timezone_config, login_banner=loginbanner_config)
    fw.add(system_config)
    system_config.create()
    print('---------------------------------------------------------------------')
    print(f"Default timezone {timezone_config} and LoginBanner configured! Moving on...")
    print('---------------------------------------------------------------------')
    print('')
    time.sleep(2)
### Hostname Config ###
def Setup_Hostname(hostname_new2):
    system_config = device.SystemSettings(hostname=hostname_new2)
    fw.add(system_config)
    system_config.create()
    print('---------------------------------------------------------------------')
    print(f"Hostname {hostname_new2} configured!")
    print('---------------------------------------------------------------------')
    print('')
    time.sleep(2)
####################################### END - Device Config Functions ########################################

####################################### START - Management Interface Functions #######################################
### Ip Address Config ###
def IpAddress_Config(mgmt_newfunc):
    system_config_ip = device.SystemSettings(ip_address=mgmt_newfunc)
    fw.add(system_config_ip)
    system_config_ip.create()
    print('---------------------------------------------------------------------')
    print(f"The IP Address {mgmt_newfunc} has been configured!")
    print('---------------------------------------------------------------------')
### Netmask Config ###
def Netmask_Config(netmask_newfunc):
    system_config_mask = device.SystemSettings(netmask=netmask_newfunc)
    fw.add(system_config_mask)
    system_config_mask.create()
    print('---------------------------------------------------------------------')
    print(f"Netmask {netmask_newfunc} has been configured!")
    print('---------------------------------------------------------------------')
### Default Gateway Config ###
def DefaultGateway_Config(defaultgateway_newfunc):
    system_config_gateway = device.SystemSettings(default_gateway=defaultgateway_newfunc)
    fw.add(system_config_gateway)
    system_config_gateway.create()
    print('---------------------------------------------------------------------')
    print(f"Default Gateway {defaultgateway_newfunc} has been configured!")
    print('---------------------------------------------------------------------')
### DNS Primary Config ###
def DnsPrimary_Config(dnsprimary_newfunc):
    system_config_primary = device.SystemSettings(dns_primary=dnsprimary_newfunc)
    fw.add(system_config_primary)
    system_config_primary.create()
    print('---------------------------------------------------------------------')
    print(f"Primary DNS {dnsprimary_newfunc} has been configured!")
    print('---------------------------------------------------------------------')
### DNS Secondary Config ###
def DnsSecondary_Config(dnssecondary_newfunc):
    system_config_secondary = device.SystemSettings(dns_secondary=dnssecondary_newfunc)
    fw.add(system_config_secondary)
    system_config_secondary.create()
    print('---------------------------------------------------------------------')
    print(f"Secondary DNS {dnssecondary_newfunc} has been configured!")
    print('---------------------------------------------------------------------')
####################################### END - Management Interface Functions ########################################

####################################### START - EDL Creation Function #######################################
#### ExternalDynamicLists Creation ####
def ExternalDynamicLists_Creation():
    ### PaloAlto-BulletproofIPadds Creation ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Objects/ExternalDynamicLists?location=vsys&vsys=vsys1&name=PaloAlto-BulletproofIPadds')
    data = {
    "entry": {
        "@name": "PaloAlto-BulletproofIPadds",
        "type": {
        "predefined-ip": {
            "description": "IP addresses that are provided bulletproof hosting providers. Bulletproof hosting providers place few, if any, restrictions on content, attackers can use these services to host and distribute malicious, illegal, and unethical material",
            "url": "panw-bulletproof-ip-list"
        }
        }
    }
    }
    creation_response = requests.post (url=api_url, headers=headers, json=data, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("ExternalDynamicLists PaloAlto-BulletproofIPadds was not created! Continuing...")
        print("CHECK THE REQUIRED LICENSE!")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    elif creation_response.status_code == 400:
        print('---------------------------------------------------------------------')
        print("ExternalDynamicLists PaloAlto-BulletproofIPadds was not created! Continuing...")
        print("CHECK THE REQUIRED LICENSE!")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("ExternalDynamicLists PaloAlto-BulletproofIPadds created successfully! Moving on...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    ### PaloAlto-TorexitIPadds Creation ###
    api_url = (f'https://{mgmt}/restapi/v{version}/Objects/ExternalDynamicLists?location=vsys&vsys=vsys1&name=PaloAlto-TorexitIPadds')
    data = {
    "entry": {
        "@name": "PaloAlto-TorexitIPadds",
        "type": {
        "predefined-ip": {
            "description": "IP addresses supplied multiple providers and validated with Palo Alto Networks threat intelligence data as active Tor exit nodes. Traffic from Tor exit nodes are disproportionately associated with malicious activity.",
            "url": "panw-torexit-ip-list"
        }
        }
    }
    }
    creation_response = requests.post (url=api_url, headers=headers, json=data, verify=False)
    if creation_response.status_code >= 200 and creation_response.status_code <- 299:
        print('---------------------------------------------------------------------')
        print("ExternalDynamicLists PaloAlto-TorexitIPadds was not created! Continuing...")
        print("CHECK THE REQUIRED LICENSE!")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    elif creation_response.status_code == 400:
        print('---------------------------------------------------------------------')
        print("ExternalDynamicLists PaloAlto-TorexitIPadds was not created! Continuing...")
        print("CHECK THE REQUIRED LICENSE!")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
    else:
        print('---------------------------------------------------------------------')
        print("ExternalDynamicLists PaloAlto-TorexitIPadds created successfully! Moving on...")
        print('Status Code: ', creation_response.status_code)
        print('Reason: ', creation_response.reason)
        print('---------------------------------------------------------------------')
####################################### END - EDL Creation Function ########################################




####################################### START - Options Menu #######################################
while option != 8:
    print('=-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-=')
    print('==-==-==-==-==-==-==-==-==-==-==-==-= Options Menu =-==-==-==-==-==-==-==-==-==-==-==-==')
    print('=-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-==-=')
    print('''    [1] Configure Best-Practices Profiles.
    [2] Configure Random Password in Admin.
    [3] Delete Default Settings.
    [4] Configure Hostname.
    [5] Configure Timezone (America/Sao_Paulo) and Login Banner.
    [6] Management Interface Settings.
    [7] EDL Configuration Best-Practices (License Required!).
    [8] Exit the Program.''')
    option = int(input("What do you want to run??! "))
    print('')
    if option == 1:
        FileBlocking_Creation()
        AntiSpyware_Creation()
        UrlFiltering_Creation()
        AntiVirus_Creation()
        VulnerabilityProtection_Creation()
        WildfireAnalysis_Creation()
        SecurityProfileGroups_Creation()
        print("Best-practices settings have been configured!")
        profiles_config = "Configured Profiles!"
        print('')
    elif option == 2:
        #### Random Password Generation ####
        ### Character Definition ###
        length=15
        characters = string.ascii_letters + string.digits
        #### Creating a random password ###
        password_new = ''.join(random.choice(characters) for i in range (length))
        #### PHASH Creation ####
        hashed_password = sha256_crypt.using(salt=None, rounds=5000).hash(password_new)
        AdminPassword_Config(hashed_password)
        ##### Creating and Writing Backup #####
        with open(f'AdminPassword_{datetime.now().strftime('%H%M%S')}.txt', 'w') as file:
            #### Writing variables ####
            file.write(f"Firewall Admin User: {mgmt}" + '\n')
            file.write("New Admin Password = " + repr(password_new) + '\n')
        ##### Script Closure #####
        print(f"PHASH random {hashed_password} set!")
    elif option == 3:
        DeleteDefaultRule()
        DeleteDefaultZone()
        DeleteDefaultVirtualRouter()
        DeleteDefaultVirtualWire()
        DeleteDefaultInterface()
        DeleteDefaultQoSProfile()
        DeleteDefaultTunnelMonitor()
        DeleteDefaultIKECrypto()
        DeleteDefaultIPSecCrypto()
        GPIPSecCryptoProfile()
        print("Default firewall settings have been deleted!")
        print("")
        choose_delete_rsp = "Deleted"
    elif option == 4:
        hostname_new = str(input("""Please inform the new Hostname!
New Hostname: """))
        print('') 
        Setup_Hostname(hostname_new)
    elif option == 5:
        Setup_Timezone_Banner()
    elif option == 6: 
        ### IP Address Configuration ###
        choose_adress = input("""
You want to configure the IP Address?
        Yes = Y
        No = N
Enter your answer: """)
        if choose_adress.lower() == "n":
            print('---------------------------------------------------------------------')
            print("IP Address will not be configured!")
            print('---------------------------------------------------------------------')
            time.sleep(2)
        elif choose_adress.lower() != "y" and choose_dnssecondary.lower() != "n":
            print('---------------------------------------------------------------------')
            print("The option entered does not exist!")
            print('---------------------------------------------------------------------')
            time.sleep(2)
        elif choose_adress.lower() == "y":
            mgmt_new = input("""
Please provide the new IP Address:
New IP Address: """)
            IpAddress_Config(mgmt_new)
        ### Netmask Configuration ###
        choose_netmask = input("""
Do you want to configure Netmask??
        Yes = Y
        No = N
Enter your answer: """)
        if choose_netmask.lower() == "n":
            print('---------------------------------------------------------------------')
            print("Netmask will not be configured!")
            print('---------------------------------------------------------------------')
            time.sleep(2)
        elif choose_netmask.lower() != "y" and choose_dnssecondary.lower() != "n":
            print('---------------------------------------------------------------------')
            print("The option entered does not exist!")
            print('---------------------------------------------------------------------')
            time.sleep(2)
        elif choose_netmask.lower() == "y":
            netmask_new = input("""
Please inform the new Netmask:
New Netmask: """)
            Netmask_Config(netmask_new)
        ### DefaultGateway Configuration ###
        choose_defaultgateway = input("""
Do you want to configure DefaultGateway?
        Yes = Y
        No = N
Enter your answer: """)
        if choose_defaultgateway.lower() == "n":
            print('---------------------------------------------------------------------')
            print("DefaultGateway will not be configured!")
            print('---------------------------------------------------------------------')
            time.sleep(2)
        elif choose_defaultgateway.lower() != "y" and choose_dnssecondary.lower() != "n":
            print('---------------------------------------------------------------------')
            print("The option entered does not exist!")
            print('---------------------------------------------------------------------')
            time.sleep(2)
        elif choose_defaultgateway.lower() == "y":
            defaultgateway_new = input("""
Please provide the new DefaultGateway:
New DefaultGateway: """)
            DefaultGateway_Config(defaultgateway_new)
        ### Primary DNS Configuration ###
        choose_dnsprimary = input("""
Do you want to configure Primary DNS?
        Yes = Y
        No = N
Enter your answer: """)
        if choose_dnsprimary.lower() == "n":
            print('---------------------------------------------------------------------')
            print("Primary DNS will not be configured!")
            print('---------------------------------------------------------------------')
            time.sleep(2)
        elif choose_dnsprimary.lower() != "y" and choose_dnssecondary.lower() != "n":
            print('---------------------------------------------------------------------')
            print("The option entered does not exist!")
            print('---------------------------------------------------------------------')
            time.sleep(2)
        elif choose_dnsprimary.lower() == "y":
            dnsprimary_new = input("""
Please enter the new Primary DNS:
New DNS Primary: """)
            DnsPrimary_Config(dnsprimary_new)
        ### Secondary DNS Configuration ###
        choose_dnssecondary= input("""
Do you want to configure Secondary DNS?
        Yes = Y
        No = N
Enter your answer: """)
        if choose_dnssecondary.lower() == "n":
            print('---------------------------------------------------------------------')
            print("Secondary DNS will not be configured!")
            print('---------------------------------------------------------------------')
            print('')
            time.sleep(2)
        if choose_dnssecondary.lower() != "y" and choose_dnssecondary.lower() != "n":
            print('---------------------------------------------------------------------')
            print("The option entered does not exist!")
            print('---------------------------------------------------------------------')
            print('')
            time.sleep(2)
        if choose_dnssecondary.lower() == "y":
            dnssecondary_new = input("""
Please enter the new Secondary DNS:
New DNS Secondary: """)
            DnsSecondary_Config(dnssecondary_new)
        ##### Creating and Writing Backup #####
        with open(f'Configurações_{datetime.now().strftime('%H%M%S')}.txt', 'w') as file:
            #### Writing variables ####
            file.write(f"Settings Applied to the {mgmt} firewall" + '\n')
            file.write("New Hostname = " + repr(hostname_new) + '\n')
            file.write("New IP Address = " + repr(mgmt_new) + '\n')
            file.write("New Netmask = " + repr(netmask_new) + '\n')
            file.write("New DefaultGateway = " + repr(defaultgateway_new) + '\n')
            file.write("New DNS Primary = " + repr(dnsprimary_new) + '\n')
            file.write("New DNS Secondary = " + repr(dnssecondary_new) + '\n')
    elif option == 7:
        ExternalDynamicLists_Creation()
    elif option == 8:
        ##### Finishing Banner #####
        print(f'-------------------------------------------------------------------------')
        print(f'---------------------------- Script Completed ---------------------------')
        print(f'-------------------------- Commit Not Executed! -------------------------')
        print(f'----------------------- Validate the Informations -----------------------')
        print(f'-------------------------------------------------------------------------')
        print(f'---------New IP Address: {mgmt_new}')
        print(f'------------New Netmask: {netmask_new}')
        print(f'-----New DefaultGateway: {defaultgateway_new}')
        print(f'--------New DNS Primary: {dnsprimary_new}')
        print(f'------New DNS Secondary: {dnssecondary_new}')
        print(f'-----New Admin Password: {password_new}')
        print(f'-----------BSP Settings: {profiles_config}')
        print(f'-------Default Settings: {choose_delete_rsp}')
        print(f'---------------------------------------------------------------------')
        input()
        exit()
    else:
        print('Invalid option. Please try again!')
        time.sleep(2)
######################################## END - Options Menu ########################################