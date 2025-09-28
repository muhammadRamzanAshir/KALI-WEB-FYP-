# 🐉 Kali Web - Web Interface for Kali Linux Tools  

## 📖 Overview  
Kali Web is a **Django-based web application** that provides a GUI interface for Kali Linux tools.  
It simplifies the usage of command-line security and penetration testing tools, making them accessible via a web browser.  

## ✨ Features  
🔎 **Network Information Module** – Displays router IP, global IP, MAC address, Ethernet, and WLAN details.  
💻 **Live Command Execution** – Run and display terminal commands directly in the web interface.  
⚙️ **Service Control** – Start and stop essential services from the web GUI.  
📂 **Dirsearch Integration** – Perform directory brute-force scanning from the web.  
⌨️ **Keylogger Module** – Capture and send keystrokes securely.  
📑 **Report Management** – Store and manage generated reports.  
🔐 **User Authentication** – Secure login system for controlled access.  

## 🛠️ Installation  

### ✅ Prerequisites  
Ensure you have the following installed on your Kali Linux system:  
- 🐍 Python 3.x  
- 🌐 Django  
- 🛡️ Required security tools (e.g., dirsearch)  

### 🚀 Steps  

1. **Clone the repository**  
   ```bash
   git clone https://github.com/your-repo/kali-web.git
   cd kali-web
### 🔧 Setup & Run

**2. Create a virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate

2. **Install dependencies**  
   ```bash
   pip install -r requirements.txt



python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
