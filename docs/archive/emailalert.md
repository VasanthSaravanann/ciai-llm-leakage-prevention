import smtplib
from email.mime.text import MIMEText

def send_alert_email(data):
    msg = MIMEText(f"User {data['user_id']} triggered detection: {data['detections']}\nPrompt: {data['redacted_prompt']}")
    msg['Subject'] = "CIAI Alert: Sensitive Data Detected"
    msg['From'] = "alerts@ciai.com"
    msg['To'] = "security@customer.com"
    # Configure SMTP server
    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls()
        server.login("your_email@gmail.com", "app_password")
        server.send_message(msg)
