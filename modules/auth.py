import requests
from instaloader import Instaloader
import imaplib

def verify_social_media(url):
    if "instagram.com" in url:
        L = Instaloader()
        try:
            profile = L.check_profile_id(url.split("/")[-2])
            return not profile.is_private
        except:
            return False
    else:
        return requests.get(url).status_code == 200

def verify_email(email, password):
    if "@gmail.com" in email:
        try:
            imap = imaplib.IMAP4_SSL("imap.gmail.com")
            imap.login(email, password)
            imap.logout()
            return True
        except:
            return False
    return True  # Placeholder for other domains
