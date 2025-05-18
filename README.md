# 🚀 Network Security Management System  
A web-based **Network Security Management System** that allows users to **block/unblock IPs & ports, view security logs, and analyze traffic** using a secure web interface.  

---

## 📌 Features  
✅ **User Authentication** – Admins can manage security settings, users have read-only access  
✅ **Block/Unblock IPs & Ports** – Restrict network access via the web interface  
✅ **API Security** – Enforces API token authentication for external access  
✅ **Command Execution via Web Interface** – No need for CLI commands  
✅ **Impact Analysis** – Recommended for SDN-based security control  
✅ **Stored Command History** – View previously executed commands  
✅ **Database Logging** – All actions are stored in an SQLite database  

---

## 📌 Installation  

### **1️⃣ Install Dependencies**  
Ensure you have **Python 3.9+** and **pip** installed.  
Then install Flask and other required packages:  
```sh
pip install flask flask-bcrypt flask-login flask-sqlalchemy

2️⃣ Clone the Repository
git clone https://github.com/yourusername/CCNPRO-Network-Security.git
cd CCNPRO-Network-Security

3️⃣ Set Up the Virtual Environment (Optional, Recommended)
python -m venv venv
venv\Scripts\activate  # For Windows
source venv/bin/activate  # For Linux/Mac

4️⃣ Initialize the Database
python -c "from database.db_handler import init_db; init_db()"

Usage
Run the Web Server
python web/app.py
✅ The web interface will be available at:

cpp
http://127.0.0.1:5000/
Username	Password	Role
admin		adminpass	admin
user1		userpass	user