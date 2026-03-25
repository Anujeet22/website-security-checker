# 🔐 AI Website Security Checker

An AI-powered desktop application that detects whether a website URL is safe or malicious using machine learning and real-time security analysis.

---

## 🚀 Features

* 🔍 AI-based phishing detection using TF-IDF + Logistic Regression
* 🔐 SSL Certificate verification
* 🌐 Google Safe Browsing API integration
* 📅 Domain age analysis using WHOIS
* 🖥️ Interactive GUI built with CustomTkinter
* 👤 Login & Registration system

---

## 🧠 How It Works

1. User enters a website URL
2. URL is converted into numerical form using TF-IDF vectorization
3. Machine learning model predicts whether the URL is safe or malicious
4. Additional checks (SSL, domain age, Safe Browsing) enhance security analysis

---

## 📸 Application Preview


### 🔐 Login Page

![Login](assets/login.png)

### 🔍 URL Scanner

![Scanner](assets/scanner.png)

### 🤖 AI Prediction Result

![AI](assets/ai_result.png)

---

## 🧰 Tech Stack

* Python
* Scikit-learn
* Pandas
* CustomTkinter
* Requests
* WHOIS
* Joblib

---

## ⚙️ Installation

```bash
git clone https://github.com/Anujeet22/website-security-checker.git
cd website-security-checker
pip install -r requirements.txt
python Login.py
```

---

## 📊 Example Output

* ✅ Safe URL → Confidence ~90%
* ⚠️ Risky URL → Risk Score ~85%

---

## 📌 Future Improvements

* MySQL integration
* Password hashing (bcrypt)
* Advanced phishing detection features
* Web deployment

---

## 👨‍💻 Author

**Anujeet Kadam**
MCA Student | AI Enthusiast

---

## ⭐ Support

If you like this project, consider giving it a ⭐ on GitHub!
