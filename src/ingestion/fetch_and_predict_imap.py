import os
import imaplib
import email
from email.header import decode_header
import joblib
from dotenv import load_dotenv

load_dotenv()  # load vars from .env file

EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")
IMAP_HOST = os.getenv("IMAP_HOST", "imap.gmail.com")
MAILBOX = os.getenv("MAILBOX", "INBOX")
MARK_AS_SEEN = False

# Load model and vectorizer paths
BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), "../.."))
MODEL_PATH = os.path.join(BASE, "artifacts", "model.pkl")
VECTORIZER_PATH = os.path.join(BASE, "artifacts", "vectorizer.pkl")

model = joblib.load(MODEL_PATH)
vectorizer = joblib.load(VECTORIZER_PATH)

def decode_mime_words(s):
    parts = decode_header(s)
    decoded = []
    for part, enc in parts:
        if isinstance(part, bytes):
            decoded.append(part.decode(enc or "utf-8", errors="ignore"))
        else:
            decoded.append(part)
    return "".join(decoded)

def get_first_text_part(msg):
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            disp = str(part.get("Content-Disposition") or "")
            if ctype == "text/plain" and "attachment" not in disp:
                payload = part.get_payload(decode=True)
                charset = part.get_content_charset() or "utf-8"
                if payload:
                    return payload.decode(charset, errors="ignore")
        return ""
    else:
        payload = msg.get_payload(decode=True)
        return payload.decode(msg.get_content_charset() or "utf-8", errors="ignore") if payload else ""

def predict_text(subject, body):
    text = (subject or "") + " " + (body or "")
    X = vectorizer.transform([text])
    score = model.predict_proba(X)[:, 1][0]
    label = "phishing" if score > 0.495 else "legitimate"
    return label, float(score)

def fetch_and_predict():
    m = imaplib.IMAP4_SSL(IMAP_HOST)
    m.login(EMAIL_USER, EMAIL_PASS)
    m.select(MAILBOX)

    status, message_numbers = m.search(None, "ALL")
    ids = message_numbers[0].split()[-100:]  # last 100 emails

    results = []
    for num in ids:
        status, msg_data = m.fetch(num, "(RFC822)")
        raw = msg_data[0][1]
        msg = email.message_from_bytes(raw)

        subject = decode_mime_words(msg.get("Subject", ""))
        sender = decode_mime_words(msg.get("From", ""))
        body = get_first_text_part(msg)

        label, score = predict_text(subject, body)

        results.append({
            "id": num.decode() if isinstance(num, bytes) else str(num),
            "from": sender,
            "subject": subject,
            "label": label,
            "score": round(score, 4)
        })

        if MARK_AS_SEEN:
            m.store(num, '+FLAGS', '\\Seen')

    m.close()
    m.logout()
    return results

if __name__ == "__main__":
    predictions = fetch_and_predict()
    for prediction in predictions:
        print(prediction)
