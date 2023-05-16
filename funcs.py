from fastapi import FastAPI
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = FastAPI()

@app.post("/send_email")
async def send_email(to_email: str, subject: str, message: str):
    # Email configuration
    smtp_server = "your_smtp_server"
    smtp_port = 587
    smtp_username = "your_smtp_username"
    smtp_password = "your_smtp_password"
    sender_email = "your_sender_email"

    # Create the email message
    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(message, "plain"))

    try:
        # Connect to the SMTP server
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_username, smtp_password)

        # Send the email
        server.sendmail(sender_email, to_email, msg.as_string())
        server.quit()

        return {"message": "Email sent successfully!"}
    except Exception as e:
        return {"message": f"Failed to send email. Error: {str(e)}"}