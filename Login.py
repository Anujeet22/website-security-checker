import json
import customtkinter as ctk
from Web_Bot import SecurityCheckerApp

USERS_FILE = "Users.json"


def load_users():
    try:
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)


class LoginApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Login")
        self.geometry("500x380")
        self.resizable(False, False)
        self.setup_ui()

    def setup_ui(self):
        ctk.CTkLabel(self, text="Login With Credentials", font=("Arial", 18, "bold")).pack(pady=20)

        self.username = ctk.CTkEntry(self, placeholder_text="Enter Username", width=300)
        self.username.pack(pady=10)

        self.password = ctk.CTkEntry(self, placeholder_text="Enter Password", width=300, show="*")
        self.password.pack(pady=10)

        ctk.CTkButton(self, text="Login", command=self.check_credentials).pack(pady=15)
        ctk.CTkButton(self, text="Register", command=self.open_register_window).pack(pady=5)

        self.status_label = ctk.CTkLabel(self, text="", text_color="red")
        self.status_label.pack(pady=5)

    def check_credentials(self):
        username = self.username.get().strip()
        password = self.password.get().strip()
        users = load_users()

        if username in users and users[username]["password"] == password:
            self.status_label.configure(text="Login successful!", text_color="green")
            self.after(500, self.open_security_checker)
        else:
            self.status_label.configure(text="Invalid username or password.", text_color="red")
            self.username.delete(0, "end")
            self.password.delete(0, "end")

    def open_register_window(self):
        window = ctk.CTkToplevel(self)
        window.title("Register")
        window.geometry("400x300")
        window.resizable(False, False)

        ctk.CTkLabel(window, text="Create Account", font=("Arial", 18, "bold")).pack(pady=20)

        new_username = ctk.CTkEntry(window, placeholder_text="Username", width=280)
        new_username.pack(pady=10)

        new_password = ctk.CTkEntry(window, placeholder_text="Password", width=280, show="*")
        new_password.pack(pady=10)

        status_label = ctk.CTkLabel(window, text="", text_color="green")
        status_label.pack(pady=5)

        def register():
            uname = new_username.get().strip()
            pword = new_password.get().strip()

            if not uname or not pword:
                status_label.configure(text="Fields cannot be empty.", text_color="red")
                return

            users = load_users()
            if uname in users:
                status_label.configure(text="Username already exists.", text_color="red")
                return

            users[uname] = {"password": pword}
            save_users(users)
            status_label.configure(text="Account created!", text_color="green")
            window.after(800, window.destroy)

        ctk.CTkButton(window, text="Register", command=register).pack(pady=10)

    def open_security_checker(self):
        self.destroy()
        app = SecurityCheckerApp()
        app.mainloop()


if __name__ == "__main__":
    app = LoginApp()
    app.mainloop()