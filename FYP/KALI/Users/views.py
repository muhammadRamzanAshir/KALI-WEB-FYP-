from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import UserCreationForm
from django.views.decorators.csrf import csrf_exempt  
from django.contrib.auth import authenticate, login
from django.views.generic import TemplateView
from django.core.files.storage import FileSystemStorage
from django.shortcuts import render, redirect
from django.http import HttpResponseBadRequest, HttpResponseNotFound, StreamingHttpResponse
from django.http import HttpResponse, JsonResponse
from django.core.files.storage import default_storage
from django.contrib import messages
from .forms import CustomSignupForm
import time
from django.conf import settings 
from django.http import Http404
import socket
from django.urls import reverse
from flask import Flask, request, jsonify
from fake_useragent import UserAgent
from bs4 import BeautifulSoup
import subprocess
import requests
import threading
from .models import PhoneDetail
import psutil
import json
import csv
import glob
import string
import ipaddress
import logging
import re
import netifaces
from scapy.all import sr1, ARP
from scapy.all import ARP, Ether, srp, conf
import os
import re
import uuid
import sys
import socket
script_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'scripts'))

# Add this path to sys.path
if script_path not in sys.path:
    sys.path.append(script_path)





# Now you can import whatweb
scan_process    = None
scan_thread     = None
macof_process   = None

class HomeView(LoginRequiredMixin, TemplateView):
    template_name = 'Users/home.html'

def index(request):
    return render(request, 'Users/index.html')

def login_view(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            # Authentication successful, redirect to 'home'
            return redirect('/home')
        else:
            messages.error(request, 'Invalid username or password.')
    
    # If not a POST request or authentication failed, render the login form
    return render(request, 'Users/login.html')

def signup_view(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            form.save()
            messages.success(request, 'Your account has been created successfully!')
            return redirect('login')
    else:
        form = UserCreationForm()
    return render(request, 'Users/signup.html', {'form': form})


@login_required
def home_view(request):
    ip, hostname, mac = get_local_network_information()
    gateway_ip, router_mac = get_router_info()
    router_host = "Gateway"
    ethernet_name, ethernet_ip, ethernet_mac = get_ethernet_info()
    global_ip = get_global_ip()
    global_name = "Global IP"
    speed_test_info = speedometer()

    # Fetch device information
    devices = get_devices_info()  # Call your function to get device info

    context = {
        "ip": ip,
        "hostname": hostname,
        "mac": mac,
        'router_host': router_host,
        "gateway_ip": gateway_ip,
        "router_mac": router_mac,
        "ethernet_name": ethernet_name,
        "ethernet_ip": ethernet_ip,
        "ethernet_mac": ethernet_mac,
        'global_ip': global_ip,
        "global_name": global_name,
        "download": speed_test_info['download'],
        "upload": speed_test_info['upload'],
        "ping": speed_test_info['ping'],
        "error": speed_test_info['error'],
        "devices": devices,  # Add the devices information to context
    }

    # Handle the case where information couldn't be retrieved
    if ip is None or hostname is None or mac is None:
        context['error'] = "Unable to retrieve network information."
    
    return render(request, 'Users/home.html', context)

def get_devices_info():
    """Fetch the device information from the backend."""
    try:
        response = requests.get('http://localhost:8000/get_device_info/')  # Update with your actual URL
        if response.status_code == 200:
            return response.json()  # Return the list of devices
        else:
            return []  # Return an empty list on error
    except requests.RequestException:
        return []  # Return an empty list if there's a request error
@login_required
def logout_view(request):
    return redirect('Users/login.html')

@login_required
def view_whatweb(request):
    return render(request, 'Users/web/whatweb.html')

def remove_spaces(string):
    return ''.join(string.split())

@csrf_exempt
def scan_with_whatweb(request):
    
    if request.method == 'POST':
        url                 = request.POST.get('url') 
        listOfPlugins       = request.POST.get('listOfPlugins')
        aggressionLevel     = request.POST.get('aggressionLevel')
        userAgent           = request.POST.get('userAgent')
        timeOut             = request.POST.get('timeOut')
        threads             = request.POST.get('threads')
        enableVerbose       = request.POST.get('enableVerbose')     == '1'
        enableRedirect      = request.POST.get('enableRedirect')    == '1'
        enableProxy         = request.POST.get('enableProxy')       == '1'
        Discoveringweb      = request.POST.get('Discoveringweb')    == '1'
        
        command = ['whatweb']
        if url:
            command.append(url)
        if listOfPlugins:
            listOfPlugins = remove_spaces(listOfPlugins)
            if listOfPlugins == 'all':
                command.append('--list-plugins')
            else:
                command.append('--plugin')
                command.append(listOfPlugins)
        if aggressionLevel:
            command.append('-a')
            command.append(aggressionLevel)
        if userAgent:
            command.append('--user-agent')
            User_Agents_Get(userAgent)
            
        if timeOut:
            command.append('--timeout')
            command.append(timeOut)
        if threads:
            command.append('--threads')
            command.append(threads)
        if enableVerbose:
            command.append('-v')
        if enableRedirect:
            command.append('--follow-redirects ')
        if enableProxy:
            # here is append command to use proxy 
            command = ['proxychains'] + command
        if Discoveringweb:
            command = []
            command.append("whatweb")
            command.append('--open')
            command.append(url)
        try:
            # Run the cewl command
            result = subprocess.run(command, capture_output=True, text=True)

            # Ensure `raw_output` is properly defined
            raw_output = result.stdout.strip()  # Strip any extra whitespace
            print(raw_output)

            # Clean the raw output by removing ANSI escape codes
            clean_output = re.sub(r'\x1B[@-_][0-?]*[ -/]*[@-~]', '', raw_output)

            logger.debug(f"Clean output from cewl: {clean_output}")

            return JsonResponse({'data': clean_output})

        except subprocess.CalledProcessError as e:
            logger.error(f"Subprocess error: {str(e)}")
            return JsonResponse({'error': str(e.stderr)}, status=500)
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return JsonResponse({'error': 'Unexpected error occurred', 'details': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=400)

@login_required
def wpscan(request):
    return render(request, 'Users/vulnerability/wpscan.html')

logger = logging.getLogger(__name__)


@csrf_exempt
def run_wpscan(request):
    if request.method == 'POST':
        url             = request.POST.get('url')  # Get the URL from POST data
        ownwordlist     = request.POST.get('ownwordlist')
        username        = request.POST.get('targetUsername')
        enum_user       = request.POST.get('enum_user')       == '1'
        enum_plugin     = request.POST.get('enum_plugin')     == '1'
        enum_themes     = request.POST.get('enum_themes')     == '1'
        vulnerable      = request.POST.get('vulnerable')      == '1'
        enumerate       = request.POST.get('enumerate')       == '1'
        passwordAttack  = request.POST.get('passwordAttack')  == '1'
        customWordlist  = request.POST.get('customWordlist')  == '1'
        rockyou         = request.POST.get('rockyou')         == '1'

        # Construct the command
        command = ['wpscan', '--url', url]
        print(command)
        
        if enumerate:
            enum_options = []
            if enum_user:
                enum_options.append('u')
            if enum_plugin:
                enum_options.append('p')
            if enum_themes:
                enum_options.append('vt')
            if enum_options:
                command.append('-e')
                command.append(','.join(enum_options))
        # Adding the vulnerable only option
        if vulnerable:
            command.append('--vulnerable-only')
        if passwordAttack:
            command.append('-u')
            command.append(username)
        if rockyou:
            command.append('-P')
            command.append('/usr/share/wordlists/rockyou.txt')
        if customWordlist:
            command.append('-P')
            command.append(ownwordlist)
        
        try:
            # Run the wpscan command and answer "yes" to any update prompts
            process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate(input="yes\n")

            if process.returncode != 0:
                logger.error(f"WPSCan error: {stderr}")
                return JsonResponse({'error': stderr}, status=500)

            raw_output = stdout.strip()  # Strip any extra whitespace
            print(raw_output)

            # Clean the raw output by removing ANSI escape codes
            clean_output = re.sub(r'\x1B[@-_][0-?]*[ -/]*[@-~]', '', raw_output)

            logger.debug(f"Clean output from wpscan: {clean_output}")

            return JsonResponse({'data': clean_output})

        except subprocess.CalledProcessError as e:
            logger.error(f"Subprocess error: {str(e)}")
            return JsonResponse({'error': str(e.stderr)}, status=500)
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return JsonResponse({'error': 'Unexpected error occurred', 'details': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=400)



@login_required
def cewl(request):
    return render(request, 'Users/password/cewl.html')



@csrf_exempt
def run_cewl(request):
    if request.method == 'POST':
        url = request.POST.get('url')  # Get the URL from POST data
        min_word_length = request.POST.get('minWordLength')
        max_word_length = request.POST.get('maxWordLength')

        # Combine min and max word lengths correctly
        min_max_word_length = f"{min_word_length},{max_word_length}" if min_word_length and max_word_length else min_word_length

        command = ['cewl']
        if min_max_word_length:
            command.append('-m')
            command.append(min_max_word_length)
        command.append(url)

        try:
            # Run the cewl command
            result = subprocess.run(command, capture_output=True, text=True)

            # Ensure `raw_output` is properly defined
            raw_output = result.stdout.strip()  # Strip any extra whitespace
            print(raw_output)

            # Clean the raw output by removing ANSI escape codes
            clean_output = re.sub(r'\x1B[@-_][0-?]*[ -/]*[@-~]', '', raw_output)

            logger.debug(f"Clean output from cewl: {clean_output}")

            return JsonResponse({'data': clean_output})

        except subprocess.CalledProcessError as e:
            logger.error(f"Subprocess error: {str(e)}")
            return JsonResponse({'error': str(e.stderr)}, status=500)
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return JsonResponse({'error': 'Unexpected error occurred', 'details': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=400)


@login_required
def nikto(request):
    return render(request, 'Users/vulnerability/nikto.html')

@csrf_exempt
def run_nikto(request):
    if request.method == 'POST':
        url             = request.POST.get('url')  # Get the URL from POST data
        Evasion         = request.POST.get('Evasion')
        cveSearch       = request.POST.get('cveSearch')
        userAgent       = request.POST.get('userAgent')
        timeOut         = request.POST.get('timeOut')
        portno          = request.POST.get('portno')
        Tuning          = request.POST.get('Tuning')
        enableVerbose   = request.POST.get('enableVerbose') == '1'
        nossl           = request.POST.get('nossl')         == '1'
        enablessl       = request.POST.get('enablessl')     == '1'
        enableProxy     = request.POST.get('enableProxy')   == '1'
        command         = []

        if enableProxy:
            command.append('proxychains')
            command.append('nikto')
        else:
            command.append('nikto')
        if url:
            command.append('-h')
            command.append(url)
        if portno:
            command.append('-p')
            command.append(portno)
        if timeOut:
            command.append('-T')
            command.append(timeOut)
        if cveSearch:
            command.append('-cve')
            command.append(cveSearch)
        if enablessl:
            command.append('-ssl')
        if nossl:
            command.append('-nossl')
        if userAgent:
            command.append('--user-agent')
            User_Agents_Get(userAgent)
        if Tuning:
            command.append('-Tuning')
            command.append(Tuning)
        if Evasion:
            command.append('-evasion')
            command.append(Evasion)
        try:
            # Run the whatweb command
            result = subprocess.run(command, capture_output=True, text=True)
            raw_output = result.stdout.strip()  # Strip any extra whitespace

            # Clean the raw output by removing ANSI escape codes
            clean_output = re.sub(r'\x1B[@-_][0-?]*[ -/]*[@-~]', '', raw_output)

            logger.debug(f"Clean output from whatweb: {clean_output}")

            return JsonResponse({'data': clean_output})

        except subprocess.CalledProcessError as e:
            logger.error(f"Subprocess error: {str(e)}")
            return JsonResponse({'error': str(e.stderr)}, status=500)
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return JsonResponse({'error': 'Unexpected error occurred', 'details': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=400)

# interfaces
def get_network_info(request):
    try:
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
    except Exception as e:
        hostname = 'Unknown'
        ip_address = f"Error occurred: {e}"

    # Return the hostname and IP address as JSON data
    return JsonResponse({'hostname': hostname, 'ip_address': ip_address})

@login_required
def dirsearch(request):
    return render(request, 'Users/web/dirsearch.html')

@csrf_exempt
def run_dirsearch(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        threads = request.POST.get('threads', '1')
        extension = request.POST.get('extension', '')

        # Ensure the threads and extensions are not empty
        if not threads.isdigit() or int(threads) < 1:
            threads = '1'  # Default to 1 if invalid
        if not extension:
            extension = 'all'  # Default to all if no extension is provided

        command = [
            'dirsearch',  # Include the path to dirsearch.py if it's not in your current directory
            '-u', url,
            '-t', threads,
            '-e', extension  # Use '-e' for extensions instead of '--extension'
        ]

        def generate_output():
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            try:
                for line in iter(process.stdout.readline, ''):
                    yield line + '<br>'  # Ensure HTML line breaks are sent
                process.stdout.close()
                process.wait()
            except Exception as e:
                yield f"Error: {str(e)}<br>"

        return StreamingHttpResponse(generate_output(), content_type='text/html')


@login_required
def cmsmap(request):
    return render(request, 'Users/web/cmsmap.html')

@csrf_exempt
def run_cmsmap(request):
    if request.method == 'POST':
        # Get the target URL and options from the POST request data
        url = request.POST.get('url')
        port = request.POST.get('port')
        time_out = request.POST.get('timeOut')
        threads = request.POST.get('threads')
        cmstype = request.POST.get('cmstype')
        enable_proxy = request.POST.get('enableProxy') == 'true'
        enable_verbose = request.POST.get(' ') == 'true'
        enable_vuln = request.POST.get('enablevuln') == 'true'
        print(enable_verbose)
        print(enable_vuln)
        # Construct the command with user-selected options
        command = ['cmsmap', url]
        
        # Add options based on the input from the frontend
        if port:
            command.append(f'--port={port}')
        if time_out:
            command.append(f'--timeout={time_out}')
        if threads:
            command.append(f'--threads={threads}')
        if cmstype:
            command.append(f'--cmstype={cmstype}')
        if enable_proxy:
            command.append('--proxy')
        if enable_verbose:
            command.append('--verbose')
        if enable_vuln:
            command.append('--enable-vuln')
    
        print(command)

        try:
            # Run the cmsmap command
            result = subprocess.run(command, capture_output=True, text=True)
            raw_output = result.stdout.strip()
            print(raw_output)

            # Clean the raw output by removing any ANSI escape codes
            clean_output = re.sub(r'\x1B[@-_][0-?]*[ -/]*[@-~]', '', raw_output)

            logger.debug(f"Clean output from cmsmap: {clean_output}")
            print(clean_output)

            return JsonResponse({'data': clean_output})

        except subprocess.CalledProcessError as e:
            logger.error(f"Subprocess error: {str(e)}")
            return JsonResponse({'error': str(e.stderr)}, status=500)
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return JsonResponse({'error': 'Unexpected error occurred', 'details': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=400)

@login_required
def dirb(request):
    return render(request, 'Users/dirb.html')

@csrf_exempt
def run_dirb(request):
    if request.method == 'POST':
        url = request.POST.get('url')  # Get the URL from POST data
        # same i can create directory to add wordlists
        command = ['dirb', url]
        try:
            print(command)
            # Run the whatweb command
            result = subprocess.run(command, capture_output=True, text=True)
            raw_output = result.stdout.strip()  # Strip any extra whitespace

            # Clean the raw output by removing ANSI escape codes
            clean_output = re.sub(r'\x1B[@-_][0-?]*[ -/]*[@-~]', '', raw_output)

            logger.debug(f"Clean output from whatweb: {clean_output}")

            return JsonResponse({'data': clean_output})

        except subprocess.CalledProcessError as e:
            logger.error(f"Subprocess error: {str(e)}")
            return JsonResponse({'error': str(e.stderr)}, status=500)
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return JsonResponse({'error': 'Unexpected error occurred', 'details': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=400)



@login_required
def netdiscover(request):
    devices = []

    try:
        # Run the arp-scan command
        output = subprocess.check_output(['sudo', 'arp-scan', '--localnet'], universal_newlines=True)
        # Process the output
        for line in output.splitlines()[2:]:  # Skip the first two header lines
            parts = line.split('\t')
            if len(parts) >= 3:
                ip = parts[0].strip()
                mac = parts[1].strip()
                vendor = parts[2].strip()
                devices.append({'ip': ip, 'mac': mac, 'vendor': vendor})
    except subprocess.CalledProcessError as e:
        print(f"Error: {e.output}")

    # Render the data in the template
    return render(request, 'Users/network/netdiscover.html', {'devices': devices})

def run_arp_scan(request):
    if request.method == 'POST':
        interface = request.POST.get('interface')
        localnet = request.POST.get('localnet') == '1'
        gateway = request.POST.get('gateway') == '1'
        passive = request.POST.get('passive') == '1'
        verbose = request.POST.get('verbose') == '1'
        version = request.POST.get('version') == '1'

        command = ['arp-scan']
        if interface:
            command.append(f'--interface={interface}')
        if localnet:
            command.append('--localnet')
        if gateway:
            command.append('--gateway')
        if passive:
            command.append('--passive')
        if verbose:
            command.append('--verbose')
        if version:
            command.append('--version')

        try:
            result = subprocess.run(command, capture_output=True, text=True)
            clean_output = result.stdout.strip()
            return JsonResponse({'data': clean_output})

        except subprocess.CalledProcessError as e:
            return JsonResponse({'error': str(e.stderr)}, status=500)
        except Exception as e:
            return JsonResponse({'error': 'Unexpected error occurred', 'details': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=400)


# function for user_agent
def User_Agents_Get(user_agent):
    ua = UserAgent()
    if user_agent == 'chrome':
        return ua.chrome
    elif user_agent == 'firefox':
        return ua.firefox
    elif user_agent == 'safari':
        return ua.safari
    elif user_agent == 'tor':
        return ua.ff
    elif user_agent == 'opera':
        return ua.google
    else:
        return ua.random


def get_local_network_information():
    try:
        # Get the local IP address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Use a valid IP address
        local_ip = s.getsockname()[0]
        s.close()
        
        # Get the hostname
        host_name = socket.gethostname()
        
        # Get the MAC address
        mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) for elements in range(0, 2*6, 2)][::-1])
        
        return local_ip, host_name, mac
    except Exception as e:
        return None, None, None  # Return None for all three values in case of n None for both values in case of an error


def get_router_info():
    try:
        # Get the router (default gateway) IP address using 'ip route'
        route_output = subprocess.check_output("ip route show default", shell=True).decode()
        gateway_ip = route_output.split()[2]  # Extract the third field, which is the gateway IP

        # Get the router MAC address using 'ip neigh' instead of 'arp' for more consistent parsing
        neigh_output = subprocess.check_output(f"ip neigh show {gateway_ip}", shell=True).decode()
        
        # The MAC address is the 5th field in 'ip neigh' output
        router_mac = neigh_output.split()[4]

        return gateway_ip, router_mac
    
    except Exception as e:
        print(f"Error: {e}")  # Print the error for debugging purposes
        return None, None

def get_ethernet_info():
    try:
        # Get Ethernet interface name (usually starts with 'eth' or 'en')
        interface_output = subprocess.check_output("ip link show | grep 'state UP'", shell=True).decode()
        interface_name = interface_output.split(":")[1].strip()

        # Get Ethernet IP address using 'ip addr'
        ip_output = subprocess.check_output(f"ip -4 addr show {interface_name}", shell=True).decode()
        ethernet_ip = ip_output.split("inet ")[1].split("/")[0]  # Extract IP address

        # Get Ethernet MAC address using 'ip link'
        link_output = subprocess.check_output(f"ip link show {interface_name}", shell=True).decode()
        ethernet_mac = link_output.split("link/ether ")[1].split()[0]  # Extract MAC address

        return interface_name, ethernet_ip, ethernet_mac
    
    except Exception as e:
        print(f"Error: {e}")
        return None, None, None

def get_global_ip():
    try:
        # Making a request to a free service to get the public IP
        response = requests.get("https://api.ipify.org?format=json")
        response.raise_for_status()  # Raise an error for bad responses
        ip_data = response.json()  # Parse the JSON response
        return ip_data['ip']  # Return the IP address
    except Exception as e:
        print(f"Error retrieving global IP: {e}")
        return None


def speedometer():
    speed_test_results = {
        'download': None,
        'upload': None,
        'ping': None,
        'error': None,
    }

    try:
        # Run the speedtest-cli command
        result = subprocess.check_output(['speedtest-cli', '--simple']).decode()

        # Parse the output
        for line in result.splitlines():
            if "Download" in line:
                speed_test_results['download'] = line.split()[1] + " " + line.split()[2]  # e.g., "50.03 Mbit/s"
            elif "Upload" in line:
                speed_test_results['upload'] = line.split()[1] + " " + line.split()[2]  # e.g., "10.12 Mbit/s"
            elif "Ping" in line:
                speed_test_results['ping'] = line.split()[1] + " ms"  # e.g., "10.00 ms"
    except subprocess.CalledProcessError as e:
        speed_test_results['error'] = "Error running speed test: " + str(e)

    return speed_test_results
@login_required
def nmap(request):
    return render(request, 'Users/nmap.html')

def run_nmap(request):
    if request.method == 'POST':
        url = request.POST.get('url') 
        singleHostScane = request.POST.get(" singleHostScane ")   == '1'
        stealthScan     = request.POST.get(" stealthScan ")       == '1'
        versionScan     = request.POST.get(" versionScan ")       == '1'
        OSscan          = request.POST.getls(" OSscan ")            == '1'
        AggressiveScan  = request.POST.get(" AggressiveScan ")    == '1'
        VerboseOutput   = request.POST.get(" VerboseOutput ")     == '1'
        normalScan      = request.POST.get(" normalScan ")        == '1'
        AdvancedScan    = request.POST.get(" AdvancedScan ")      == '1'

        command = ['nmap',url]
        if stealthScan:
            command.append('-sS')
        if versionScan:
            command.append('-sV')
        if OSscan:
            command.append('-O')
        if AggressiveScan:
            command.append('-A')
        if VerboseOutput:
            command.append('-v')
        if normalScan:
            command.append('')
        try:
            print(command)
            # Run the whatweb command
            result = subprocess.run(command, capture_output=True, text=True)
            raw_output = result.stdout.strip()  # Strip any extra whitespace

            # Clean the raw output by removing ANSI escape codes
            clean_output = re.sub(r'\x1B[@-_][0-?]*[ -/]*[@-~]', '', raw_output)

            logger.debug(f"Clean output from whatweb: {clean_output}")

            return JsonResponse({'data': clean_output})

        except subprocess.CalledProcessError as e:
            logger.error(f"Subprocess error: {str(e)}")
            return JsonResponse({'error': str(e.stderr)}, status=500)
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return JsonResponse({'error': 'Unexpected error occurred', 'details': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=400)

@login_required
def nuclei(request):
    return render(request, 'Users/web/nuclei.html')

@csrf_exempt
def run_nuclei(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        timeOut = request.POST.get('timeOut')
        enableProxy = request.POST.get('enableProxy') == '1'
        enableVerbose = request.POST.get('enableVerbose') == '1'
        silentMode = request.POST.get('silentMode') == '1'

        # Build command based on received data
        command = ['nuclei']  # Nuclei command

        if enableProxy:
            command.append('-proxy')  # Adding proxy flag for nuclei
        if enableVerbose:
            command.append('-v')  # Adding verbose flag for nuclei
        if silentMode:
            command.append('-silent')  # Adding silent mode flag for nuclei

        if url:
            command.append('-u')
            command.append(url)  # Adding URL argument
        if timeOut:
            command.append('-timeout')
            command.append(timeOut)  # Adding timeout argument

        try:
            # Execute the nuclei command
            result = subprocess.run(command, capture_output=True, text=True)
            raw_output = result.stdout.strip()  # Strip extra whitespace
            clean_output = re.sub(r'\x1B[@-_][0-?]*[ -/]*[@-~]', '', raw_output)  # Clean output

            logger.debug(f"Clean output from Nuclei: {clean_output}")

            return JsonResponse({'data': clean_output})

        except subprocess.CalledProcessError as e:
            logger.error(f"Subprocess error: {str(e)}")
            return JsonResponse({'error': str(e.stderr)}, status=500)
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return JsonResponse({'error': 'Unexpected error occurred', 'details': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=400)

@login_required
def macof(request):
    return render(request, 'Users/network/macof.html')


def macof_controller(request):
    global macof_process
    if request.method == 'POST':
        action = request.POST.get('action')
        interface = request.POST.get('interface')

        if action == 'start':
            # If a process is already running, don't start a new one
            if macof_process is not None:
                return JsonResponse({'status': 'Already running'}, status=400)

            try:
                # Start the macof process
                macof_process = subprocess.Popen(
                    ["macof"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                return JsonResponse({'status': f'Macof started on {interface}'})
            except Exception as e:
                return JsonResponse({'error': 'Failed to start macof', 'details': str(e)}, status=500)

        elif action == 'stop':
            # Stop the macof process if it's running
            if macof_process is not None:
                macof_process.terminate()  # Terminate the process
                macof_process = None
                return JsonResponse({'status': 'Macof stopped'})
            else:
                return JsonResponse({'error': 'Macof is not running'}, status=400)

        return JsonResponse({'error': 'Invalid action'}, status=400)

    return JsonResponse({'error': 'Invalid request method'}, status=400)

@login_required
def nmap(request):
    return render(request, 'Users/information/nmap.html')

@csrf_exempt
def run_nmap(request):
    if request.method == 'POST':
        url         = request.POST.get('url')
        portno      = request.POST.get('portno')
        scanType    = request.POST.get('scantype')
        timing      = request.POST.get('timing')
        command     = ['nmap']
        if url:
            command.append(url)
        if portno:
            command.append("-p")
            command.append(portno)
        if scanType:
            match scanType:
                case 1:
                    command.append("-sS")
                case 2:
                    command.append("-sT")
                case 3:
                    command.append("-sU")
                case 4:
                    command.append("-sA")
                case 5:
                    command.append("-Pn")
                case 6:
                    command.append("-sV")
                case 7:
                    command.append("o")
                case 8:
                    command.append("-A")
        if timing:
            match timing:
                case 1:
                    command.append("-T0")
                case 2:
                    command.append('-T1')
                case 3:
                    command.append("T2")
                case 4:
                    command.append("T3")
                case 5:
                    command.append("T4")
                case 6:
                    command.append("T5")
        print(command)
        try:
            # Execute the nuclei command
            result = subprocess.run(command, capture_output=True, text=True)
            raw_output = result.stdout.strip()  # Strip extra whitespace
            clean_output = re.sub(r'\x1B[@-_][0-?]*[ -/]*[@-~]', '', raw_output)  # Clean output

            logger.debug(f"Clean output from Nuclei: {clean_output}")

            return JsonResponse({'data': clean_output})

        except subprocess.CalledProcessError as e:
            logger.error(f"Subprocess error: {str(e)}")
            return JsonResponse({'error': str(e.stderr)}, status=500)
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return JsonResponse({'error': 'Unexpected error occurred', 'details': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=400)
        
@login_required
def dimitry(request):
    return render(request, 'Users/information/dimitry.html')        


@csrf_exempt
def run_dimitry(request):
    if request.method == 'POST':
        url              = request.POST.get('url')
        whois            = request.POST.get('whois')        == '1'
        subdomains       = request.POST.get('subdomains')   == '1'
        emails           = request.POST.get('emails')       == '1'
        ports            = request.POST.get('ports')        == '1'
        traceroute       = request.POST.get('traceroute')   == '1'
 
        # Build command based on received data
        command = ['dmitry']  # Nuclei command

        if url:
            command.append(url)
        if whois:
            command.append("-w")
        if subdomains:
            command.append("-s")
        if emails:
            command.append("-e")
        if ports:
            command.append("-p")
        if traceroute:
            command.append('-t')
        try:
            # Execute the nuclei command
            result = subprocess.run(command, capture_output=True, text=True)
            raw_output = result.stdout.strip()  # Strip extra whitespace
            clean_output = re.sub(r'\x1B[@-_][0-?]*[ -/]*[@-~]', '', raw_output)  # Clean output

            logger.debug(f"Clean output from Nuclei: {clean_output}")

            return JsonResponse({'data': clean_output})

        except subprocess.CalledProcessError as e:
            logger.error(f"Subprocess error: {str(e)}")
            return JsonResponse({'error': str(e.stderr)}, status=500)
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return JsonResponse({'error': 'Unexpected error occurred', 'details': str(e)}, status=500)

        return JsonResponse({'error': 'Invalid request method'}, status=400)
    
@login_required
def whois(request):
    return render(request, 'Users/information/whois.html')       

@csrf_exempt
def run_whois(request):
    if request.method == 'POST':
        url              = request.POST.get('url')

        # Build command based on received data
        command = ['whois']  # Nuclei command

        if url:
            command.append(url)
        try:
            # Execute the nuclei command
            result = subprocess.run(command, capture_output=True, text=True)
            raw_output = result.stdout.strip()  # Strip extra whitespace
            clean_output = re.sub(r'\x1B[@-_][0-?]*[ -/]*[@-~]', '', raw_output)  # Clean output

            logger.debug(f"Clean output from Nuclei: {clean_output}")

            return JsonResponse({'data': clean_output})

        except subprocess.CalledProcessError as e:
            logger.error(f"Subprocess error: {str(e)}")
            return JsonResponse({'error': str(e.stderr)}, status=500)
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return JsonResponse({'error': 'Unexpected error occurred', 'details': str(e)}, status=500)

        return JsonResponse({'error': 'Invalid request method'}, status=400)

@login_required
def theharvester(request):
    return render(request, 'Users/information/theharvester.html')

@csrf_exempt
def run_theharvester(request):
    if request.method == 'POST':
        url              = request.POST.get('url')
        no_of_result     = request.POST.get('no_of_result')
        sources          = request.POST.get('sources')          

        
        # Build command based on received data
        command = ['theHarvester']  # Nuclei command

        if url:
            command.append('-d')
            command.append(url)
        try:
            # Execute the nuclei command
            result = subprocess.run(command, capture_output=True, text=True)
            raw_output = result.stdout.strip()  # Strip extra whitespace
            clean_output = re.sub(r'\x1B[@-_][0-?]*[ -/]*[@-~]', '', raw_output)  # Clean output

            logger.debug(f"Clean output from Nuclei: {clean_output}")

            return JsonResponse({'data': clean_output})

        except subprocess.CalledProcessError as e:
            logger.error(f"Subprocess error: {str(e)}")
            return JsonResponse({'error': str(e.stderr)}, status=500)
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return JsonResponse({'error': 'Unexpected error occurred', 'details': str(e)}, status=500)

        return JsonResponse({'error': 'Invalid request method'}, status=400)


@login_required
def sqlmap(request):
    return render(request, 'Users/vulnerability/sqlmap.html')


@csrf_exempt
def run_sqlmap(request):
    if request.method == 'POST':
        url              = request.POST.get('url')
        stype            = request.POST.get('stype')
        rlevel           = request.POST.get('rlevel')
        slevel           = request.POST.get('slevel')
        vlevel           = request.POST.get('vlevel')
        clevel           = request.POST.get('clevel')
        enableProxy      = request.POST.get('enableProxy')           == '1'
        enabletor        = request.POST.get('enabletor')           == '1'
        enableretrive    = request.POST.get('enableretrive')           == '1'
        print(url)
        print(stype)
        print(rlevel)
        print(slevel)
        print(vlevel)
        print(clevel)
        print(enableProxy)
        print(enableretrive)
        
        stype = int(stype) if stype else None
        rlevel = int(rlevel) if rlevel else None
        slevel = int(slevel) if slevel else None
        vlevel = int(vlevel) if vlevel else None
        clevel = int(clevel) if clevel else None
        # Build command based on received data
        command = ['sqlmap']  # Nuclei command
        if enableProxy:
            command.insert(0,"proxychains")

        if url:
            command.append('-u')
            command.append(url)
    
        if stype:
            match stype:
                case 1:
                    command.append("--dbs")
                case 2:
                    command.append("--tables")
                case 3:
                    command.append("--tables")
                case 4:
                    command.append("--colums")
                case 5:
                    command.append("--dump")
        if rlevel:
            match rlevel:
                case 1:
                    command.append("--risk=1")
                case 2:
                    command.append("--risk=2")
                case 3:
                    command.append("--risk=3")
        if slevel:
            match slevel:
                case 1:
                    command.append("--level=1")
                case 2:
                    command.append("--level=2")
                case 3:
                    command.append("--level=3")
        if vlevel:
            match vlevel:
                case 1:
                    command.append('--verbose=1')
                case 2:
                    command.append('--verbose=2')
                case 3:
                    command.append('--verbose=3')
                case 4:
                    command.append('--verbose=4')
                case 5:
                    command.append('--verbose=5')
                case 6:
                    command.append('--verbose=6')
        if clevel:
            match clevel:
                case 1:
                    command.append('--crawl=2')
                case 2:
                    command.append('--crawl=4')
                case 3:
                    command.append('--crawl=6')
                case 4:
                    command.append('--crawl=8')
                case 5:
                    command.append('--crawl=10')
        if enableretrive:
            command.append("--all")
        print(command)
        try:
            # Execute the nuclei command
            result = subprocess.run(command, capture_output=True, text=True)
            raw_output = result.stdout.strip()  # Strip extra whitespace
            clean_output = re.sub(r'\x1B[@-_][0-?]*[ -/]*[@-~]', '', raw_output)  # Clean output

            logger.debug(f"Clean output from Nuclei: {clean_output}")

            return JsonResponse({'data': clean_output})

        except subprocess.CalledProcessError as e:
            logger.error(f"Subprocess error: {str(e)}")
            return JsonResponse({'error': str(e.stderr)}, status=500)
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return JsonResponse({'error': 'Unexpected error occurred', 'details': str(e)}, status=500)

        return JsonResponse({'error': 'Invalid request method'}, status=400)



@login_required
def joomscan(request):
    return render(request, 'Users/vulnerability/joomscan.html')


@csrf_exempt
def run_joomscan(request):
    if request.method == 'POST':
        url              = request.POST.get('url')
        userAgent        = request.POST.get('userAgent')
        timeOut          = request.POST.get('timeOut')
        enableProxy      = request.POST.get('enableProxy')           == '1'
        enableCompnoents = request.POST.get('enableCompnoents')           == '1'
        
        # Build command based on received data
        command = ['joomscan']  # Nuclei command
        if enableProxy:
            command.insert(0,"proxychains")

        if url:
            command.append('-u')
            command.append(url)

        if userAgent:
            if userAgent == "random":
                command.append("-r")
            else:
                command.append('--user-agent')
                User_Agents_Get(userAgent)
        
        if enableCompnoents:
            command.append("-ec")
        
        if timeOut:
            command.append("--timeout")
            command.append(timeOut)
        print(command)
        try:
            # Execute the nuclei command
            result = subprocess.run(command, capture_output=True, text=True)
            raw_output = result.stdout.strip()  # Strip extra whitespace
            clean_output = re.sub(r'\x1B[@-_][0-?]*[ -/]*[@-~]', '', raw_output)  # Clean output

            logger.debug(f"Clean output from Nuclei: {clean_output}")

            return JsonResponse({'data': clean_output})

        except subprocess.CalledProcessError as e:
            logger.error(f"Subprocess error: {str(e)}")
            return JsonResponse({'error': str(e.stderr)}, status=500)
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return JsonResponse({'error': 'Unexpected error occurred', 'details': str(e)}, status=500)

        return JsonResponse({'error': 'Invalid request method'}, status=400)

@login_required
def john(request):
    hashes_dir = os.path.join(settings.MEDIA_ROOT, 'hashes')
    hash_files = [f for f in os.listdir(hashes_dir) if f.endswith('.hash')]

    return render(request, 'Users/password/john.html', {
        'hash_files': hash_files
    })


@csrf_exempt
def run_john(request):
    if request.method == "POST":
        hash_file = request.POST.get('hash_file')
        is_cracked = request.POST.get('isCracked')
        print(is_cracked)

        if not hash_file:
            return JsonResponse({'error': 'No hash file selected.'}, status=400)

        # Full path to the hash file
        hash_file_path = os.path.join(settings.MEDIA_ROOT, 'hashes', hash_file)
        command = ['john']
        if is_cracked == 'true':  # Check if the checkbox is marked
            command.append("--show")
        command.append(hash_file_path)
        print(command)

        try:
            # Execute the John the Ripper command
            result = subprocess.run(
                command, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True
            )
            
            if result.returncode == 0:
                # Parse the output for the cracked password
                output_lines = result.stdout.strip().split('\n')
                
                if is_cracked == 'true':
                    # Extract the line with the cracked password
                    for line in output_lines:
                        if ':' in line and not line.startswith('1 password hash'):
                            cracked_password = line.split(':')[1]  # Extract password after the colon
                            return JsonResponse({'password': cracked_password})
                else:
                    return JsonResponse({'success': 'John is running to crack the hash.'})
            else:
                return JsonResponse({'error': result.stderr.strip()}, status=500)

        except Exception as e:
            return JsonResponse({'error': f'Error running John the Ripper: {str(e)}'}, status=500)

    return JsonResponse({'error': 'Invalid request.'}, status=400)


@login_required
@csrf_exempt
def zip2john(request):
    hashes_dir = os.path.join(settings.MEDIA_ROOT, 'hashes')
    os.makedirs(hashes_dir, exist_ok=True)

    if request.method == 'POST' and request.FILES.get('zip_file'):
        # Save the uploaded ZIP file
        zip_file = request.FILES['zip_file']
        fs = FileSystemStorage(location=os.path.join(settings.MEDIA_ROOT, 'uploads'))
        filename = fs.save(zip_file.name, zip_file)
        uploaded_file_path = os.path.join(settings.MEDIA_ROOT, 'uploads', filename)

        # Generate the hash using zip2john
        hash_file_path = os.path.join(hashes_dir, f"{os.path.splitext(filename)[0]}.zip.hash")

        try:
            with open(hash_file_path, 'w') as hash_file:
                subprocess.run(['zip2john', uploaded_file_path], stdout=hash_file, check=True)
            hash_file_url = f"{settings.MEDIA_URL}hashes/{os.path.basename(hash_file_path)}"
        except subprocess.CalledProcessError as e:
            return render(request, 'Users/other/zip2john.html', {'error': f"Error processing the file: {e}"})

        return render(request, 'Users/other/zip2john.html', {'hash_file_url': hash_file_url})

    # List existing hash files
    hash_files = []
    for file_name in os.listdir(hashes_dir):
        file_path = os.path.join(hashes_dir, file_name)
        hash_files.append({
            'name': file_name,
            'download_url': f"{settings.MEDIA_URL}hashes/{file_name}",
            'delete_url': f"/zip2john/delete/{file_name}"  # Create this route for deletion
        })

    return render(request, 'Users/other/zip2john.html', {'hash_files': hash_files})



@csrf_exempt
def delete_hash_file(request, file_name, type):
    if request.method == 'POST':
        # Sanitize the filename to avoid directory traversal
        sanitized_file_name = os.path.basename(file_name)
        
        # For zip2john
        if type == '1':
            hash_file_path = os.path.join(settings.MEDIA_ROOT, 'hashes', sanitized_file_name)
            if os.path.exists(hash_file_path):
                os.remove(hash_file_path)
            else:
                return HttpResponseNotFound(f"File {sanitized_file_name} not found in the 'hashes' directory.")
            return redirect('zip2john')
        
        # For dictionary (crunch)
        elif type == '2':
            dictionary_file_path = os.path.join(settings.MEDIA_ROOT, 'dictionary', sanitized_file_name)
            if os.path.exists(dictionary_file_path):
                os.remove(dictionary_file_path)
            else:
                return HttpResponseNotFound(f"File {sanitized_file_name} not found in the 'dictionary' directory.")
            return redirect('crunch')

        else:
            return HttpResponseBadRequest("Invalid file type provided.")
    return HttpResponseBadRequest("Invalid request method. Please use POST to delete the file.")

@login_required
def hydra(request):
    return render(request, 'Users/password/hydra.html')


@csrf_exempt
def hydra_cracker(request):
    if request.method == 'POST':
        try:
            # Get form data
            target = request.POST.get('target')
            port = request.POST.get('port')
            method = request.POST.get('method')
            threads = request.POST.get('threads', 4)
            username_file = request.FILES.get('uwordlist')
            password_file = request.FILES.get('pwordlist')

            # Validate input
            if not all([target, port, method, username_file, password_file]):
                return JsonResponse({'error': 'All fields are required!'}, status=400)

            # Save uploaded files to the media directory
            username_file_path = os.path.join(settings.MEDIA_ROOT, 'uploads', username_file.name)
            password_file_path = os.path.join(settings.MEDIA_ROOT, 'uploads', password_file.name)

            os.makedirs(os.path.dirname(username_file_path), exist_ok=True)

            with open(username_file_path, 'wb') as f:
                for chunk in username_file.chunks():
                    f.write(chunk)

            with open(password_file_path, 'wb') as f:
                for chunk in password_file.chunks():
                    f.write(chunk)

            # Construct the Hydra command
            command = [
                'hydra',
                '-L', username_file_path,
                '-P', password_file_path,
                '-t', str(threads),
                '-s', port,
                method,
                target
            ]

            # Execute Hydra command
            result = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            # Check the results
            if result.returncode == 0:
                output = result.stdout.splitlines()
                cracked_credentials = [line for line in output if 'login:' in line and 'password:' in line]

                if cracked_credentials:
                    return JsonResponse({'success': True, 'data': cracked_credentials})
                else:
                    return JsonResponse({'success': False, 'message': 'No valid credentials found.'})
            else:
                return JsonResponse({'success': False, 'error': result.stderr.strip()}, status=500)

        except Exception as e:
            return JsonResponse({'error': f'An error occurred: {str(e)}'}, status=500)

    return JsonResponse({'error': 'Invalid request method.'}, status=400)

@login_required
def crunch(request):
    # List existing files
    dictionary_dir = os.path.join(settings.MEDIA_ROOT, 'dictionary')
    os.makedirs(dictionary_dir, exist_ok=True)

    hash_files = []
    for file_name in os.listdir(dictionary_dir):
        file_path = os.path.join(dictionary_dir, file_name)

        # Ensure download URL matches the directory structure of the file
        hash_files.append({
            'name': file_name,
            'download_url': f"{settings.MEDIA_URL}dictionary/{file_name}",
            'delete_url': f"/delete_file/{file_name}/2/"  # Fixing the delete URL route
        })

    return render(request, 'Users/password/crunch.html', {'hash_files': hash_files})

def run_crunch_view(request):
    if request.method == "POST":
        file_name =  request.POST.get("fileName")
        appended_letters = request.POST.get("appendedLatters")
        min_range = request.POST.get("minRange", 1)
        max_range = request.POST.get("maxRange", 3)
        # Corrected file path construction
        output_file_path = os.path.join(settings.MEDIA_ROOT, 'dictionary', '')  
        command = ['crunch']
        command.append(min_range)
        command.append(max_range)
        if appended_letters:
            command.append(appended_letters)
        file_name = 'output_file.txt'
        full_output_path = os.path.join(output_file_path, file_name)
        command.append('-o')
        command.append(full_output_path)
        print(command)  # For debugging purposes
        try:
            # Execute the nuclei command
            result = subprocess.run(command, capture_output=True, text=True)
            raw_output = result.stdout.strip()  # Strip extra whitespace
            clean_output = re.sub(r'\x1B[@-_][0-?]*[ -/]*[@-~]', '', raw_output)  # Clean output

            logger.debug(f"Clean output from Nuclei: {clean_output}")

            return JsonResponse({'data': clean_output})

        except subprocess.CalledProcessError as e:
            logger.error(f"Subprocess error: {str(e)}")
            return JsonResponse({'error': str(e.stderr)}, status=500)
        except Exception as e:
            logger.error(f"Unexpected error: {str(e)}")
            return JsonResponse({'error': 'Unexpected error occurred', 'details': str(e)}, status=500)

        return JsonResponse({'error': 'Invalid request method'}, status=400)

@login_required
def tgpt(request):
    return render(request, 'Users/other/tgpt.html')


def chat(request):
    if request.method == 'POST':
        user_message = request.POST.get('message')
        
        if user_message:
            command = ["tgpt", user_message]
            
            try:
                # Execute the tgpt command with the user message
                result = subprocess.run(command, capture_output=True, text=True)
                raw_output = result.stdout.strip()  # Strip extra whitespace
                
                # Clean all Loading lines and unwanted symbols using a broader regex
                clean_output = re.sub(r'^[\u2B6E-\u2B7F]+.*Loading.*\n*', '', raw_output, flags=re.MULTILINE)  # Remove all Loading lines
                
                # Remove any unwanted unicode symbols (including loading indicators) that persist
                clean_output = re.sub(r'[\u2B6E-\u2B7F]+', '', clean_output)  # Remove loading-related symbols
                clean_output = clean_output.strip()  # Remove leading/trailing spaces
                
                # Check if output is empty and provide a fallback message
                if not clean_output:
                    clean_output = "No meaningful response from tgpt."
                
                # Log clean output for debugging purposes
                logger.debug(f"Cleaned Output: {clean_output}")

                return JsonResponse({'data': clean_output})

            except subprocess.CalledProcessError as e:
                logger.error(f"Subprocess error: {str(e)}")
                return JsonResponse({'error': str(e.stderr)}, status=500)
            except Exception as e:
                logger.error(f"Unexpected error: {str(e)}")
                return JsonResponse({'error': 'Unexpected error occurred', 'details': str(e)}, status=500)
        else:
            return JsonResponse({'error': 'No message provided'}, status=400)

    return JsonResponse({'error': 'Invalid request method'}, status=400)

@login_required
def mdk3(request):
    return render(request, 'Users/network/mdk3.html')


def execute_mdk3(request):
    # Get parameters from the GET request
    interface = request.GET.get('interface', 'wlan0mon')  # Default to 'wlan0mon'
    channel = request.GET.get('channel')  # Get the channel from the request
    ap_mac = request.GET.get('ap_mac')  # Get the AP MAC address from the request
    jam_all = request.GET.get('jamAll', 'false') == 'true'  # Check if 'jamAll' is true

    try:
        if jam_all:
            # Command to open xterm for airodump-ng (monitor Wi-Fi before jamming)
            airodump_command = f"xterm -hold -e 'airodump-ng {interface}'"
            subprocess.Popen(airodump_command, shell=True)

            # Wait for airodump-ng to initialize
            time.sleep(5)  # Adjust delay as needed

            # Command to jam all Wi-Fi networks using mdk3
            mdk3_command = f"xterm -hold -e 'mdk3 {interface} d'"
            subprocess.Popen(mdk3_command, shell=True)

            return JsonResponse({'success': True, 'message': 'Jamming all Wi-Fi networks using mdk3.'})

        # Ensure specific parameters are provided for targeted deauth
        if not channel or not ap_mac:
            return JsonResponse({'error': 'Channel and AP MAC are required for a targeted attack.'}, status=400)

        # Command to open xterm for airodump-ng
        airodump_command = f"xterm -hold -e 'airodump-ng {interface} --channel {channel}'"
        subprocess.Popen(airodump_command, shell=True)

        # Wait for airodump-ng to initialize
        time.sleep(5)  # Adjust delay as needed

        # Command to open another xterm for mdk3
        mdk3_command = f"xterm -hold -e 'mdk3 {interface} d -c {channel} -t {ap_mac}'"
        subprocess.Popen(mdk3_command, shell=True)

        return JsonResponse({'success': True, 'message': 'Commands executed for targeted deauth in xterm.'})

    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=500)
    
    
@csrf_exempt
def manage_service(request):
    """
    Manage services dynamically via AJAX.
    """
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            service_name = data.get('service_name')
            action = data.get('action')
            
            if service_name and action in ['start', 'stop']:
                result = subprocess.run(
                    ["sudo", "service", service_name, action], 
                    stdout=subprocess.PIPE, 
                    stderr=subprocess.PIPE, 
                    text=True
                )
                if result.returncode == 0:
                    return JsonResponse({"status": "success", "message": f"Service {service_name} {action}ed successfully."})
                else:
                    return JsonResponse({"status": "error", "message": result.stderr})
            else:
                return JsonResponse({"status": "error", "message": "Invalid service name or action."})
        except Exception as e:
            return JsonResponse({"status": "error", "message": str(e)})
    return JsonResponse({"status": "error", "message": "Invalid request method."})

# Function to get mobile details
@login_required
def infoga(request):
    return render(request, "Users/osint/phoneifno.html")


@login_required
def get_mobile_details(request):
    if request.method == "POST":
        # Get the query from the POST request
        query = request.POST.get("query")
        if not query:
            return JsonResponse({"error": "No query provided"}, status=400)
        
        # Define the URL and headers
        url = "https://www.simdata.store/"
        headers = {
            "Cookie": "PHPSESSID=b2f50bc4ecc59c46046d2a812419c935; _gcl_au=1.1.1366805211.1734018718; yneEinx=1",
            "Cache-Control": "max-age=0",
            "Sec-Ch-Ua": '"Chromium";v="129", "Not=A?Brand";v="8"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Linux"',
            "Accept-Language": "en-US,en;q=0.9",
            "Origin": "https://www.simdata.store",
            "Content-Type": "application/x-www-form-urlencoded",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.6668.71 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
            "Referer": "https://www.simdata.store/",
            "Accept-Encoding": "gzip, deflate, br",
            "Priority": "u=0, i"
        }

        # Define the POST data
        data = {"query": query}

        try:
            # Send POST request
            response = requests.post(url, headers=headers, data=data)
            response.raise_for_status()  # Raise error for bad HTTP status

            # Parse the response content
            soup = BeautifulSoup(response.text, "html.parser")
            table = soup.find("table")
            
            if not table:
                return JsonResponse({"error": "No table found in response"}, status=404)

            # Extract table rows
            rows = table.find("tbody").find_all("tr")
            table_data = []

            for row in rows:
                row_data = {}
                for cell in row.find_all("td"):
                    key = cell.get("data-label", "Unknown").strip()
                    value = cell.text.strip()
                    row_data[key] = value
                table_data.append(row_data)

            # Return table data as JSON
            return JsonResponse({"data": table_data}, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    else:
        return render(request, "Users/osint/phoneifno.html")
    
def save_phone_detail(request):
    if request.method == 'POST':
        # Get the phone details from the request
        try:
            data = json.loads(request.POST.get('phoneDetail'))  # The data sent from the frontend
            
            # Create a new PhoneDetail object and save it to the database
            phone_detail = PhoneDetail(
                number=data['number'],
                name=data['name'],
                father_name=data['father_name'],
                cnic=data['cnic'],
                address=data['address']
            )
            phone_detail.save()

            # Return success response
            return JsonResponse({'status': 'success', 'message': 'Phone detail saved successfully.'})
        
        except json.JSONDecodeError:
            return JsonResponse({'status': 'error', 'message': 'Invalid data format.'})
        
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})

    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'})

def geolocation_tool(request):
    """Handle IP geolocation and result display/download in a single view."""
    results = []
    
    if request.method == "POST":
        ips = request.POST.get("ips", "")
        ip_list = [ip.strip() for ip in ips.split(',')]
        results = [fetch_geolocation(ip) for ip in ip_list]
        
        # Handle CSV download if requested
        if 'download' in request.POST:
            response = HttpResponse(content_type='text/csv')
            response['Content-Disposition'] = 'attachment; filename="geolocation_results.csv"'
            writer = csv.DictWriter(response, fieldnames=["IP", "Country", "Region", "City", "ISP", "Latitude", "Longitude", "Error"])
            writer.writeheader()
            writer.writerows(results)
            return response
    
    # Render the single HTML template for both input and results
    return render(request, 'Users/network/ip_info.html', {'results': results})


def fetch_geolocation(ip):
    """Fetch geolocation data for an IP address using ip-api.com."""
    url = f"http://ip-api.com/json/{ip}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            if data['status'] == 'success':
                return {
                    "IP": ip,
                    "Country": data.get('country', 'N/A'),
                    "Region": data.get('regionName', 'N/A'),
                    "City": data.get('city', 'N/A'),
                    "ISP": data.get('isp', 'N/A'),
                    "Latitude": data.get('lat', 'N/A'),
                    "Longitude": data.get('lon', 'N/A'),
                }
            else:
                return {"IP": ip, "Error": data.get('message', 'Unknown error')}
        else:
            return {"IP": ip, "Error": f"HTTP {response.status_code}"}
    except requests.RequestException as e:
        return {"IP": ip, "Error": str(e)}