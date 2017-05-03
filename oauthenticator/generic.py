"""
Custom Authenticator to use generic OAuth2 with JupyterHub
"""


import json
import os
import base64

from tornado.auth import OAuth2Mixin
from tornado import gen, web

from tornado.httputil import url_concat
from tornado.httpclient import HTTPRequest, AsyncHTTPClient

from jupyterhub.auth import LocalAuthenticator

from traitlets import Unicode, Dict

from .oauth2 import OAuthLoginHandler, OAuthenticator

# Support github.com and github enterprise installations
#GITHUB_HOST = os.environ.get('GITHUB_HOST') or 'github.com'
#if GITHUB_HOST == 'github.com':
#    GITHUB_API = 'api.github.com/user'
#else:
#    GITHUB_API = '%s/api/v3/user' % GITHUB_HOST


class GenericEnvMixin(OAuth2Mixin):
    #_OAUTH_AUTHORIZE_URL = "https://%s/login/oauth/authorize" % GITHUB_HOST
    #_OAUTH_ACCESS_TOKEN_URL = "https://%s/login/oauth/access_token" % GITHUB_HOST
    _OAUTH_AUTHORIZE_URL = "https://oauthasservices-b4230efae.us1.hana.ondemand.com/oauth2/api/v1/authorize?response_type=code&client_id=cfee7772-3950-345e-9e1a-80927098fa6b"
    _OAUTH_ACCESS_TOKEN_URL = "https://oauthasservices-b4230efae.us1.hana.ondemand.com/oauth2/api/v1/token"
   

class GenericLoginHandler(OAuthLoginHandler, GenericEnvMixin):
    pass


class GenericOAuthenticator(OAuthenticator):
	

    f = open('myfile', 'w+')
    f.write('Making Token Request\n')  # python will convert \n to os.linesep
    f.close()

    login_service = "GenericOAuth2"

    login_handler = GenericLoginHandler

    userdata_url = Unicode(
        'https://testservice1b4230efae.us1.hana.ondemand.com/testservice-1.0-SNAPSHOT', 
        config=True,
        help="Userdata url to get user data login information"
    )
    username_key = Unicode(
        os.environ.get('OAUTH2_USERNAME_KEY', 'username'),
        config=True,
        help="Userdata username key from returned json for USERDATA_URL"
    )
    userdata_params = Dict(
        os.environ.get('OAUTH2_USERDATA_PARAMS', {}),
        help="Userdata params to get user data login information"
    ).tag(config=True)

    userdata_method = Unicode(
        os.environ.get('OAUTH2_USERDATA_METHOD', 'GET'),
        config=True,
        help="Userdata method to get user data login information"
    )

    token_url = Unicode(
        os.environ.get('OAUTH2_TOKEN_URL', 'GET'),
        config=True,
        help="Userdata method to get user data login information"
    )

    @gen.coroutine
    def authenticate(self, handler, data=None):
        code = handler.get_argument("code", False)
        if not code:
            raise web.HTTPError(400, "oauth callback made without a token")
        # TODO: Configure the curl_httpclient for tornado
        http_client = AsyncHTTPClient()

        params = dict(
            redirect_uri=self.get_callback_url(handler),
            code=code,
            grant_type='authorization_code',
	    client_id=self.client_id,
            client_secret=self.client_secret
        )

        url = url_concat(self.token_url, params)
        
        b64key = base64.b64encode(
            bytes(
                "{}:{}".format(self.client_id, self.client_secret),
                "utf8"
            )
         )
        f = open('myfile', 'a')
        f.write('Base 64 Encoded Auth Key\n')
        f.write(str(b64key))
        f.close()

        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "Basic {}".format(b64key.decode("utf8"))
        }

        f = open('myfile', 'a')
        f.write('Request URL for the Token\n')
        f.write(url)
        f.close()

        req = HTTPRequest(url,
                          method="POST",
                          headers=headers,
                          body=''  # Body is required for a POST...
                          )

        resp = yield http_client.fetch(req)

        resp_json = json.loads(resp.body.decode('utf8', 'replace'))
        
        f = open('myfile', 'a')
        f.write(str(resp_json))
        f.close()

        access_token = resp_json['access_token']
        token_type = resp_json['token_type']
        f = open('myfile', 'a')
        f.write('Access Token Successful')
        f.write(access_token)
        f.close()
        # Determine who the logged in user is
        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "{} {}".format(token_type, access_token)
        }
        url = url_concat(self.userdata_url, self.userdata_params)
        f = open('myfile', 'a')
        f.write(str(url))
        f.close()

        req = HTTPRequest(url,
                          method=self.userdata_method,
                          headers=headers,
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))
        f = open('myfile', 'a')
        f.write(str(resp_json))
        f.close()

        if resp_json.get(self.username_key):
            return resp_json[self.username_key]


class LocalGenericOAuthenticator(LocalAuthenticator, GenericOAuthenticator):

    """A version that mixes in local system user creation"""
    pass
