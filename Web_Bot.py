import os
import re
import sys
import ssl
import socket
import ctypes
import webbrowser
import threading
import requests
import whois
import joblib
import validators
import tkinter as tk
from urllib.parse import quote_plus, urlparse
from datetime import datetime
from tkinter import messagebox, filedialog
from dotenv import load_dotenv
from cefpython3 import cefpython as cef
import customtkinter as ctk


ctypes.windll.shcore.SetProcessDpiAwareness(1)

load_dotenv()
API_KEY = os.getenv("GOOGLE_API_KEY")
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

URL_PATTERN = re.compile(
    r"^(https?:\/\/)?"
    r"(([a-z\d-]+)\.([a-z\.]{2,6}))"
    r"(\/[\"'\w\.-]*)*\/?$",
    re.IGNORECASE
)

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("dark-blue")


class SecurityCheckerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Website Security Checker")
        self.geometry("800x600")
        self.resizable(False, False)

        self.model, self.vectorizer = joblib.load("url_model.pkl")

        self.create_widgets()
        self.setup_connection_indicator()

    def create_widgets(self):
        self.create_top_bar()
        self.create_input_section()
        self.create_tabview()
        self.create_bottom_bar()

    def create_top_bar(self):
        top_frame = ctk.CTkFrame(self, height=70, corner_radius=0)
        top_frame.pack(fill="x", side="top")
        ctk.CTkLabel(top_frame, text="Website Security Checker", font=("Arial", 24, "bold")).pack(pady=20)

    def create_input_section(self):
        input_frame = ctk.CTkFrame(self)
        input_frame.pack(pady=15, padx=20, fill="x")

        self.url_entry = ctk.CTkEntry(input_frame, placeholder_text="Enter website URL")
        self.url_entry.pack(side="left", expand=True, fill="x", padx=5)

        ctk.CTkButton(input_frame, text="Scan", command=self.start_scan).pack(side="left", padx=5)

        self.progress_label = ctk.CTkLabel(self, text="", text_color="green")
        self.progress_label.pack()

    def create_tabview(self):
        self.tabview = ctk.CTkTabview(self, height=360)
        self.tabview.pack(pady=20, padx=20, fill="both", expand=True)

        self.tab_ssl = self.tabview.add("SSL")
        self.tab_safe = self.tabview.add("Safe Browsing")
        self.tab_age = self.tabview.add("Domain Age")
        self.tab_phish = self.tabview.add("Phishing Info")
        self.tab_ai = self.tabview.add("AI Prediction")

        for tab in [self.tab_ssl, self.tab_safe, self.tab_age, self.tab_phish, self.tab_ai]:
            ctk.CTkLabel(tab, text="Scan result will appear here.", font=("Arial", 14)).pack(pady=20)

    def create_bottom_bar(self):
        bottom_frame = ctk.CTkFrame(self, height=60)
        bottom_frame.pack(side="bottom", fill="x", pady=10)

        self.theme_toggle = ctk.CTkSwitch(bottom_frame, text="Dark Mode", command=self.toggle_theme)
        self.theme_toggle.select()
        self.theme_toggle.pack(side="left", padx=20)

        ctk.CTkButton(bottom_frame, text="Export", command=self.export_report).pack(side="right", padx=10)
        ctk.CTkButton(bottom_frame, text="Preview Website", command=self.preview_website).pack(side="right")

    def setup_connection_indicator(self):
        self.connection_status_label = ctk.CTkLabel(self, text="Checking...", text_color="gray", font=("Arial", 12))
        self.connection_status_label.place(relx=0.98, rely=0.03, anchor="ne")
        self.update_connection_status()

    def update_connection_status(self):
        if self.check_internet_connection():
            self.connection_status_label.configure(text="Online", text_color="green")
        else:
            self.connection_status_label.configure(text="Offline", text_color="red")
        self.after(5000, self.update_connection_status)

    @staticmethod
    def check_internet_connection(test_url="http://www.google.com", timeout=5):
        try:
            requests.get(test_url, timeout=timeout)
            return True
        except Exception:
            return False

    def toggle_theme(self):
        ctk.set_appearance_mode("Dark" if self.theme_toggle.get() else "Light")

    def start_scan(self):
        if not self.check_internet_connection():
            messagebox.showwarning("No Internet", "You are offline. Please connect to the internet.")
            self.progress_label.configure(text="Offline.", text_color="red")
            return

        url = self.clean_and_validate_url(self.url_entry.get().strip())
        if not url:
            messagebox.showwarning("Invalid URL", "Please enter a valid website URL.")
            return

        self.progress_label.configure(text="Scanning...", text_color="yellow")
        threading.Thread(target=self.run_checks, args=(url,), daemon=True).start()

    def run_checks(self, url):
        try:
            domain = self.extract_domain(url)
            ssl_status = self.check_ssl(url)
            domain_info = self.get_domain_info(domain)
            safe_browsing = self.check_safe_browsing(url)
            ai_prediction = self.predict_url_safety(url)
            self.display_results(ssl_status, domain_info, safe_browsing, url, ai_prediction)
        except Exception as e:
            self.progress_label.configure(text=f"Error: {str(e)}", text_color="red")

    def display_results(self, ssl_result, domain_result, safe_result, url, ai_result):
        self.progress_label.configure(text="Scan complete", text_color="green")

        for tab in [self.tab_ssl, self.tab_safe, self.tab_age, self.tab_phish, self.tab_ai]:
            for widget in tab.winfo_children():
                widget.destroy()

        self.show_result(self.tab_ssl, ssl_result)
        self.show_result(self.tab_safe, safe_result)
        self.show_result(self.tab_age, domain_result)

        self.show_result(self.tab_phish, "You can report this site if it looks suspicious.")
        phish_url = f"https://safebrowsing.google.com/safebrowsing/report_phish/?url={quote_plus(url)}"
        ctk.CTkButton(self.tab_phish, text="Report Phishing", command=lambda: self.open_url(phish_url)).pack(pady=10)

        ctk.CTkLabel(self.tab_ai, text="AI Prediction", font=("Arial", 18, "bold")).pack(pady=10)
        self.show_result(self.tab_ai, ai_result)

    def show_result(self, tab, result):
        safe_words = ["safe", "secure", "valid", "created", "expires", "trusted", "not phishing"]
        color = "green" if any(w in result.lower() for w in safe_words) else "red"
        ctk.CTkLabel(tab, text=result, font=("Arial", 16), text_color=color, wraplength=700).pack(pady=20)

    def preview_website(self):
        url = self.clean_and_validate_url(self.url_entry.get().strip())
        if not url:
            messagebox.showwarning("Invalid URL", "Please enter a valid website URL.")
            return

        popup = tk.Toplevel(self)
        popup.title("Website Preview")
        popup.geometry("1024x768")

        frame = tk.Frame(popup, width=1024, height=768)
        frame.pack(fill="both", expand=True)
        popup.update_idletasks()

        def start_browser():
            sys.excepthook = cef.ExceptHook
            cef.Initialize()
            window_info = cef.WindowInfo()
            rect = [0, 0, frame.winfo_width(), frame.winfo_height()]
            window_info.SetAsChild(frame.winfo_id(), rect)
            cef.CreateBrowserSync(window_info, url=url)
            cef.MessageLoop()
            cef.Shutdown()

        threading.Thread(target=start_browser, daemon=True).start()
        popup.protocol("WM_DELETE_WINDOW", popup.destroy)

    def open_url(self, url):
        webbrowser.open(url)

    def export_report(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, "w") as f:
                f.write("Website Security Report\n")
                f.write("URL: " + self.url_entry.get() + "\n")
            messagebox.showinfo("Export", "Report saved successfully.")

    def check_ssl(self, url):
        try:
            hostname = urlparse(url).hostname
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    issuer = dict(x[0] for x in cert["issuer"])["organizationName"]
                    valid_to = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    days_left = (valid_to - datetime.utcnow()).days
                    return f"SSL is secure\nIssuer: {issuer}\nValid until: {valid_to.strftime('%Y-%m-%d')} ({days_left} days left)"
        except Exception:
            return "SSL not secure or not available"

    def get_domain_info(self, domain):
        try:
            info = whois.whois(domain)
            creation = info.creation_date[0] if isinstance(info.creation_date, list) else info.creation_date
            expiry = info.expiration_date[0] if isinstance(info.expiration_date, list) else info.expiration_date
            if creation and expiry:
                age_days = (datetime.utcnow() - creation).days
                return f"Created: {creation.strftime('%Y-%m-%d')}\nExpires: {expiry.strftime('%Y-%m-%d')}\nAge: {age_days} days"
            return "Partial domain info found"
        except Exception as e:
            return f"Could not retrieve domain info: {e}"

    def check_safe_browsing(self, url):
        payload = {
            "client": {"clientId": "SecurityChecker", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        try:
            res = requests.post(
                f"{SAFE_BROWSING_URL}?key={API_KEY}",
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10
            )
            res.raise_for_status()
            return "Website is safe" if not res.json().get("matches") else "Website is dangerous"
        except requests.exceptions.RequestException as e:
            return f"Safe Browsing error: {e}"

    def clean_and_validate_url(self, url):
        if not url.startswith("http"):
            url = "https://" + url
        return url if URL_PATTERN.match(url) and validators.url(url) else None

    def extract_domain(self, url):
        return urlparse(url).netloc

    def predict_url_safety(self, url):
        try:
            features = self.vectorizer.transform([url])
            prediction = self.model.predict(features)[0]
            proba = self.model.predict_proba(features)[0]

            classes = self.model.classes_
            prob_dict = dict(zip(classes, proba))

            # If labels are strings
            if "phishing" in classes:
                if prediction == "phishing":
                    risk = prob_dict.get("phishing", 0) * 100
                    return f"Verdict: Risky URL\nRisk Score: {risk:.2f}%"
                else:
                    safe_conf = prob_dict.get("benign", 0) * 100
                    return f"Verdict: Safe URL\nConfidence: {safe_conf:.2f}%"

            # If labels are numeric (0/1)
            else:
                risk = prob_dict.get(1, 0) * 100
            if prediction == 1:
                return f"Verdict: Risky URL\nRisk Score: {risk:.2f}%"
            else:
                return f"Verdict: Safe URL\nConfidence: {100 - risk:.2f}%"

        except Exception as e:
            return f"AI Prediction Error: {str(e)}" 
        
if __name__ == "__main__":
    from Login import LoginApp
    sys.excepthook = cef.ExceptHook
    app = LoginApp()
    app.mainloop()