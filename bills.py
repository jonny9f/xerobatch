import requests
from flask import Flask, request, redirect, session, url_for
from flask_oauthlib.contrib.client import OAuth, OAuth2Application
from flask_session import Session
import webbrowser
import os
import logging
import time
import sys
from secret import CLIENT_ID, CLIENT_SECRET

from xero_python.api_client import ApiClient, serialize
from xero_python.api_client.configuration import Configuration
from xero_python.api_client.oauth2 import OAuth2Token
from xero_python.accounting import AccountingApi
from xero_python.exceptions import AccountingBadRequestException, PayrollUkBadRequestException
from xero_python.identity import IdentityApi

logging.basicConfig(format='%(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', level=logging.DEBUG)
logger = logging.getLogger(__name__)


app = Flask(__name__)
app.config.from_object("default_settings")
app.config.from_pyfile('secret.py', silent=True)
logger.debug("client id %s", app.config["CLIENT_ID"])

REDIRECT_URI = 'http://localhost:5000/callback'

# Xero URLs
AUTH_URL = 'https://login.xero.com/identity/connect/authorize'
TOKEN_URL = 'https://identity.xero.com/connect/token'
RESOURCE_URL = 'https://api.xero.com/api.xro/2.0/Invoices'  # Example resource
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"


# This variable will store our access token
g_token = None


# configure persistent session cache
Session(app)

# configure flask-oauthlib application
oauth = OAuth(app)
xero = oauth.remote_app(
    name="xero",
    version="2",
    client_id=app.config["CLIENT_ID"],
    client_secret=app.config["CLIENT_SECRET"],
    endpoint_url="https://api.xero.com/",
    authorization_url="https://login.xero.com/identity/connect/authorize",
    access_token_url="https://identity.xero.com/connect/token",
    refresh_token_url="https://identity.xero.com/connect/token",
    scope="offline_access openid profile email accounting.transactions "
    "accounting.transactions.read accounting.reports.read "
    "accounting.journals.read accounting.settings accounting.settings.read "
    "accounting.contacts accounting.contacts.read accounting.attachments "
    "accounting.attachments.read assets projects "
    "files "
    "payroll.employees payroll.payruns payroll.payslip payroll.timesheets payroll.settings",
)  # type: OAuth2Application

# configure xero-python sdk client
api_client = ApiClient(
    Configuration(
        debug=app.config["DEBUG"],
        oauth2_token=OAuth2Token(
            client_id=app.config["CLIENT_ID"], client_secret=app.config["CLIENT_SECRET"]
        ),
    ),
    pool_threads=1,
)

# configure token persistence and exchange point between flask-oauthlib and xero-python
@xero.tokengetter
@api_client.oauth2_token_getter
def obtain_xero_oauth2_token():
    return session.get("token")

@xero.tokensaver
@api_client.oauth2_token_saver
def store_xero_oauth2_token(token):
    session["token"] = token
    logger.debug("token %s", token)
    global g_token
    g_token = token

    session.modified = True


@app.route("/login")
def login():
    redirect_url = url_for("oauth_callback", _external=True)
    session["state"] = app.config["STATE"]
    try:
        response = xero.authorize(callback_uri=redirect_url, state=session["state"])
    except Exception as e:
        print(e)
        raise
    return response

@app.route("/callback")
def oauth_callback():
    if request.args.get("state") != session["state"]:
        return "Error, state doesn't match, no token for you."
    try:
        response = xero.authorized_response()
    except Exception as e:
        print(e)
        raise
    if response is None or response.get("access_token") is None:
        return "Access denied: response=%s" % response
    store_xero_oauth2_token(response)
    return "Sucessfully authorized with Xero!"

def get_xero_tenant_id():
    
    global g_token
    access_token = g_token["access_token"]

    headers = {'Authorization': f'Bearer {access_token}', 'Accept': 'application/json'}
    response = requests.get("https://api.xero.com/connections", headers=headers)
    connections = response.json()
    for connection in connections:
        if connection["tenantType"] == "ORGANISATION":
            return connection["tenantId"]


def get_invoices():
    """Makes an API request to get invoices"""
    global g_token
    access_token = g_token["access_token"]

    xero_tenant_id = get_xero_tenant_id()

    headers = {'Authorization': f'Bearer {access_token}', "Xero-tenant-id": xero_tenant_id, 'Accept': 'application/json'}
    response = requests.get(RESOURCE_URL, headers=headers)
    return response.json()


if __name__ == '__main__':
    # Start the Flask server in a separate process
    import threading
    threading.Thread(target=lambda: app.run(port=5000)).start()

    # Open the web browser for the user to login
    webbrowser.open('http://localhost:5000/login')


    ## Wait for the user to login, make the text blue to indicate this
    print("\033[94m \nWaiting for login...\033[0m\n", end='')

    ## poll for acess token
    while g_token is None:
        print('\033[94m.\033[0m', end='')
        # flush the buffer
        sys.stdout.flush()

        time.sleep(0.2)
   
        


    # Making an API request
    try:
        invoices = get_invoices()

    except Exception as e:
        print('Error making API request:', e)

    for invoice in invoices["Invoices"]:
        print(invoice['Type'], invoice["InvoiceNumber"], invoice["Total"])

