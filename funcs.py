from fastapi import FastAPI
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig

app = FastAPI()

# Mail configuration
conf = ConnectionConfig(
    MAIL_USERNAME="nicemltstng@outlook.com",
    MAIL_PASSWORD="Valtech123",
    MAIL_FROM="nicemltstng@outlook.com",
    MAIL_PORT=587,
    MAIL_SERVER="smtp.office365.com",
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False
)

mail = FastMail(conf)



