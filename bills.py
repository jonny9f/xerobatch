import requests
from flask import Flask, request, redirect
import webbrowser
import os
import logging
import time
from secret import CLIENT_ID, CLIENT_SECRET

logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', level=logging.DEBUG)
logger = logging.getLogger(__name__)


app = Flask(__name__)


REDIRECT_URI = 'http://localhost:5000/callback'

# Xero URLs
AUTH_URL = 'https://login.xero.com/identity/connect/authorize'
TOKEN_URL = 'https://identity.xero.com/connect/token'
RESOURCE_URL = 'https://api.xero.com/api.xro/2.0/Invoices'  # Example resource

# This variable will store our access token
access_token = None


@app.route('/')
def index():
    """Starts the OAuth process"""
    auth_request_url = f'{AUTH_URL}?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope=offline_access accounting.transactions'
    return redirect(auth_request_url)


@app.route('/callback')
def callback():
    """Handles the OAuth callback, exchanges code for token"""
    global access_token
    auth_code = request.args.get('code')
    token_exchange_data = {
        'grant_type': 'authorization_code',
        'code': auth_code,
        'redirect_uri': REDIRECT_URI
    }
    response = requests.post(TOKEN_URL, data=token_exchange_data, auth=(CLIENT_ID, CLIENT_SECRET))
    access_token = response.json().get('access_token')
    logger.debug( "login successful %s", access_token)
    return 'Authentication successful, you can close this window.'


def get_invoices():
    """Makes an API request to get invoices"""
    headers = {'Authorization': f'Bearer {access_token}', 'Accept': 'application/json'}
    response = requests.get(RESOURCE_URL, headers=headers)
    return response.json()


if __name__ == '__main__':
    # Start the Flask server in a separate process
    import threading
    threading.Thread(target=lambda: app.run(port=5000)).start()

    # Open the web browser for the user to login
    webbrowser.open('http://localhost:5000')

    ## Wait for the user to login, make the text blue to indicate this
    print("\033[94m \nWaiting for login...\033[0m\n", end='')

    ## poll for acess token
    while access_token is None:
        time.sleep(0.2)
        pass

    

    # Making an API request
    try:
        invoices = get_invoices()
        print('Invoices:', invoices)
    except Exception as e:
        print('Error making API request:', e)
