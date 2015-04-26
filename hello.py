"""
    Core Hello-World
    Matthew Glinski
    MIT Licensed
    Since: v0.0.1
"""

from __future__ import unicode_literals

from binascii import unhexlify
from hashlib import sha256

from flask import Flask, redirect, url_for, abort, request, jsonify
from braveapi.client import API
from ecdsa.keys import SigningKey, VerifyingKey
from ecdsa.curves import NIST256p


app = Flask(__name__)

# API Config section
config = {'api.endpoint': "https://core.braveineve.com/api",
          'api.identity': "54b01524b9e8004584706088",
          'api.private': "849b10732e95071a0de884169509e86eb168f09f3b93e915c641389f634043b6",
          'api.public': "69a2f199e301b7bb92ff264ec2f78e11a11d2ad17f3b7d1398c04dbf123f3e7d19c893614c79abb67dd8f14fde78e80132268527bfd96cd8727a8ef4bf0cb6b2"}

"""
    Config Data Documentation
    -------------------------
    api.endpoint: Url of the CORE API server your connecting to. Must not have a trailing '/', usually points to /api on the deployed domain
    api.identity: The ID of your registered application on the application management page in Core
    api.private: Your applications Private ECDSA Key as generated in the config() function
    api.public: The Core API server's Public ECDSA Key, printed in HEX on the application management page.

    ECDSA Key Guide
    -------------------------
    When you generate a ECDSA Key Pair, you need to make note of the Private key. You can always re-generate the Public key by
    knowing the private key and the Curve used to generate the private key.

    Core Application Setup
    -------------------------
    Once you have your ECDSA key pair, you need to configure the details above in the config dictionary.
    !!This note is VERY IMPORTANT!!
    You use the Core Server's Public Key in the api.public config setting, NOT YOUR PUBLIC KEY.
    You use YOUR private key in the api.private config section.
    You supply YOUR PUBLIC KEY to the Core Server when registering your application. NOT YOUR PRIVATE KEY.
    Once you complete application registration, you click the app name under your applications to get the
    identifer ID and the servers Public key. You can then start making signed requests.

"""

# Root URI
@app.route('/')
def config():
    # Load and validate the format of our auth config data
    try:
        config['api.identity']
        config['api.private'] = SigningKey.from_string(unhexlify(config['api.private']), curve=NIST256p, hashfunc=sha256)
        config['api.public'] = VerifyingKey.from_string(unhexlify(config['api.public']), curve=NIST256p, hashfunc=sha256)
    except:
        private = SigningKey.generate(NIST256p, hashfunc=sha256)

        error_message = "Core Service API identity, public, or private key missing.<br /><br />\n\n"

        error_message += "Here's a new private key; update the api.private setting to reflect this.<br />\n" + \
                         "%s <br /><br />\n\n" % private.to_string().encode('hex')

        error_message += "Here's that key's public key; this is what you register with Core.<br />\n" + \
                         "%s <br /><br /><br />\n\n" % private.get_verifying_key().to_string().encode('hex')

        error_message += "After registering, save the server's public key to api.public " + \
                         "and your service's ID to api.identity.<br /><br />"

        return error_message

    # config data looks good, allow auth attempt
    return '<a href="'+url_for('authorize')+'">Click here to auth</a>'


# Perform the initial API call and direct the user.
@app.route('/authorize')
def authorize():

    # Convert Key text into objects
    config['api.private'] = SigningKey.from_string(unhexlify(config['api.private']), curve=NIST256p, hashfunc=sha256)
    config['api.public'] = VerifyingKey.from_string(unhexlify(config['api.public']), curve=NIST256p, hashfunc=sha256)

    # Build API Client for CORE Services
    api = API(config['api.endpoint'], config['api.identity'], config['api.private'], config['api.public'])

    # Build Success/Failure Redirect URLs
    success = str("http://"+app.config['SERVER_NAME']+url_for('authorized'))
    failure = str("http://"+app.config['SERVER_NAME']+url_for('fail'))

    # Make the authentication call to the CORE Service
    result = api.core.authorize(success=success, failure=failure)

    # Redirect based on the authentication request validity
    return redirect(result.location)


# Root URI
@app.route('/authorized')
def authorized():
    # Perform the initial API call and direct the user.

    # Convert Key text into objects
    config['api.private'] = SigningKey.from_string(unhexlify(config['api.private']), curve=NIST256p, hashfunc=sha256)
    config['api.public'] = SigningKey.from_string(unhexlify(config['api.public']), curve=NIST256p, hashfunc=sha256)

    # Build API Client for CORE Services
    api = API(config['api.endpoint'], config['api.identity'], config['api.private'], config['api.public'])

    # Build Success/Failure Redirect URLs
    token = request.args.get('token', '')

    if token == '':
        abort(401)

    # Make the authentication call to the CORE Service
    result = api.core.info(token=token)

    return jsonify(result)


# Root URI
@app.route('/fail')
def fail():
    abort(401)


# App startup if running file directly
if __name__ == '__main__':
    app.run(debug=True)
