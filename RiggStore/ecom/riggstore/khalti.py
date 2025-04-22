import requests
from django.conf import settings

def initiate_khalti_payment(order_id, amount, return_url):
    url = "https://dev.khalti.com/api/v2/epayment/initiate/"
    
    payload = {
        "return_url": return_url,
        "website_url": settings.SITE_URL,
        "amount": int(amount * 100),  # Convert to paisa
        "purchase_order_id": str(order_id),
        "purchase_order_name": f"Order_{order_id}",
    }
    
    headers = {
        "Authorization": f"Key {settings.KHALTI_SECRET_KEY}",
        "Content-Type": "application/json",
    }
    
    response = requests.post(url, json=payload, headers=headers)
    return response.json()