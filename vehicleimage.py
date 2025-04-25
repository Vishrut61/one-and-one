from dotenv import load_dotenv
from twilio.rest import Client
import os
import random
import face_recognition
import cv2
import pytesseract
import tkinter as tk
from tkinter import simpledialog, messagebox, filedialog
import numpy as np
import sqlite3
import base64
import datetime
import csv
import pandas as pd

# Load environment variables
load_dotenv(dotenv_path=".env")
TWILIO_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_NUMBER = os.getenv("TWILIO_PHONE_NUMBER")

# Tesseract path
pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

DB_PATH = "car_security.db"
ADMIN_PASSWORD = "admin123"
EXCEL_DB = "license_data.xlsx"

# Database setup
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS owner (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    face_encoding TEXT NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS login_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_name TEXT,
                    timestamp TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS emergency_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    phone_number TEXT,
                    timestamp TEXT)''')
    conn.commit()
    conn.close()

def log_login(name):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO login_logs (user_name, timestamp) VALUES (?, ?)", (name, timestamp))
    conn.commit()
    conn.close()

def log_emergency(phone):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("INSERT INTO emergency_log (phone_number, timestamp) VALUES (?, ?)", (phone, timestamp))
    conn.commit()
    conn.close()

def send_otp_via_twilio(phone, otp):
    client = Client(TWILIO_SID, TWILIO_TOKEN)
    message = client.messages.create(
        body=f"Your OTP for Car Access is: {otp}",
        from_=TWILIO_NUMBER,
        to=phone
    )
    return message.sid

# GUI App
class CarSecurityApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Car Security System")
        self.root.geometry("600x500")

        tk.Label(root, text="Car Security System", font=("Helvetica", 16)).pack(pady=20)
        tk.Button(root, text="Register User Face", width=30, command=self.register_face_protected).pack(pady=10)
        tk.Button(root, text="Authenticate & Unlock Car", width=30, command=self.authenticate).pack(pady=10)
        tk.Button(root, text="Emergency User Login (OTP)", width=30, command=self.emergency_login).pack(pady=10)
        tk.Button(root, text="Admin: View Logs", width=30, command=self.admin_login).pack(pady=10)
        tk.Button(root, text="Exit", width=30, command=self.exit_app).pack(pady=10)

    def register_face_protected(self):
        pw = simpledialog.askstring("Admin Password", "Enter admin password:", show="*")
        if pw == ADMIN_PASSWORD:
            self.register_face()
        else:
            messagebox.showerror("Access Denied", "Wrong admin password.")

    def register_face(self):
        cap = cv2.VideoCapture(0)
        name = simpledialog.askstring("Registration", "Enter your name:")
        if not name:
            return
        messagebox.showinfo("Registration", "Press 's' to capture your face.")
        while True:
            ret, frame = cap.read()
            cv2.imshow("Register Face", frame)
            if cv2.waitKey(1) & 0xFF == ord('s'):
                rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                face_locations = face_recognition.face_locations(rgb_frame)
                if face_locations:
                    encoding = face_recognition.face_encodings(rgb_frame, face_locations)[0]
                    self.save_face_to_db(name, encoding)
                    messagebox.showinfo("Success", "Face registered successfully.")
                else:
                    messagebox.showerror("Error", "No face detected.")
                break
        cap.release()
        cv2.destroyAllWindows()

    def save_face_to_db(self, name, encoding):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        encoding_str = base64.b64encode(encoding.tobytes()).decode('utf-8')
        c.execute("INSERT INTO owner (name, face_encoding) VALUES (?, ?)", (name, encoding_str))
        conn.commit()
        conn.close()

    def get_all_faces(self):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT name, face_encoding FROM owner")
        rows = c.fetchall()
        conn.close()
        known_names = []
        known_encodings = []
        for name, encoding_str in rows:
            encoding = np.frombuffer(base64.b64decode(encoding_str), dtype=np.float64)
            known_names.append(name)
            known_encodings.append(encoding)
        return known_names, known_encodings

    def authenticate(self):
        known_names, known_encodings = self.get_all_faces()
        if not known_names:
            messagebox.showerror("Error", "No registered users.")
            return

        cap = cv2.VideoCapture(0)
        messagebox.showinfo("Authentication", "Press 'c' to capture face.")
        user_name = None

        while True:
            ret, frame = cap.read()
            cv2.imshow("Face Authentication", frame)
            if cv2.waitKey(1) & 0xFF == ord('c'):
                rgb_frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
                face_locations = face_recognition.face_locations(rgb_frame)
                if face_locations:
                    encoding = face_recognition.face_encodings(rgb_frame, face_locations)[0]
                    results = face_recognition.compare_faces(known_encodings, encoding, tolerance=0.5)
                    if True in results:
                        index = results.index(True)
                        user_name = known_names[index]
                        messagebox.showinfo("Face Match", f"Face recognized as {user_name}. Proceed to DL verification.")
                    else:
                        messagebox.showerror("Denied", "Face not recognized.")
                else:
                    messagebox.showerror("Error", "No face detected.")
                break
        cap.release()
        cv2.destroyAllWindows()

        if user_name:
            self.verify_license(user_name)

    def verify_license(self, user_name="Guest"):
        cap = cv2.VideoCapture(0)
        messagebox.showinfo("License Scan", "Hold your DL. Press 'd' to scan.")
        verified = False
        while True:
            ret, frame = cap.read()
            cv2.imshow("License Verification", frame)
            if cv2.waitKey(1) & 0xFF == ord('d'):
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                text = pytesseract.image_to_string(gray)
                try:
                    df = pd.read_excel(EXCEL_DB)
                    for _, row in df.iterrows():
                        if str(row['DL Number']) in text and row['Name'].lower() in text.lower():
                            if row['Name'].lower() == user_name.lower():
                                verified = True
                            break
                except Exception as e:
                    messagebox.showerror("Error", f"Excel error: {e}")
                break
        cap.release()
        cv2.destroyAllWindows()

        if verified:
            messagebox.showinfo("Access Granted", f"Welcome {user_name}! Ignition enabled.")
            log_login(user_name)
        else:
            messagebox.showerror("Access Denied", "DL not verified or name mismatch.")

    def emergency_login(self):
        phone = simpledialog.askstring("Emergency Access", "Enter your mobile number (+91...):")
        if not phone:
            return
        otp = str(random.randint(100000, 999999))
        try:
            send_otp_via_twilio(phone, otp)
            user_input = simpledialog.askstring("OTP", f"OTP sent to {phone}. Enter OTP:")
            if user_input == otp:
                messagebox.showinfo("OTP Verified", "Welcome guest. Ignition enabled without DL verification.")
                log_emergency(phone)
                log_login(f"Emergency: {phone}")
                self.exit_app()
            else:
                messagebox.showerror("Invalid", "Incorrect OTP.")
        except Exception as e:
            messagebox.showerror("Twilio Error", str(e))

    def admin_login(self):
        pw = simpledialog.askstring("Admin Login", "Enter password:", show="*")
        if pw == ADMIN_PASSWORD:
            self.show_logs()
        else:
            messagebox.showerror("Denied", "Wrong password.")

    def show_logs(self):
        logs_window = tk.Toplevel(self.root)
        logs_window.title("Login Logs")
        logs_window.geometry("500x300")

        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT user_name, timestamp FROM login_logs ORDER BY timestamp DESC")
        logs = c.fetchall()
        conn.close()

        text = tk.Text(logs_window, state=tk.NORMAL)
        text.pack(fill=tk.BOTH, expand=True)
        text.insert(tk.END, "User Name\t\tTimestamp\n")
        text.insert(tk.END, "-"*50 + "\n")
        for name, time in logs:
            text.insert(tk.END, f"{name}\t\t{time}\n")
        text.config(state=tk.DISABLED)

        tk.Button(logs_window, text="Export to CSV", command=self.export_logs_to_csv).pack(pady=10)

    def export_logs_to_csv(self):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT user_name, timestamp FROM login_logs")
        logs = c.fetchall()
        conn.close()
        file_path = filedialog.asksaveasfilename(defaultextension=".csv", title="Save Log File", filetypes=[("CSV Files", "*.csv")])
        if file_path:
            with open(file_path, mode='w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["User Name", "Timestamp"])
                writer.writerows(logs)
            messagebox.showinfo("Exported", f"Logs exported to {file_path}")

    def exit_app(self):
        self.root.destroy()

if __name__ == "__main__":
    init_db()
    root = tk.Tk()
    app = CarSecurityApp(root)
    root.mainloop()
