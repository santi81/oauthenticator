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
    _OAUTH_AUTHORIZE_URL = os.environ.get('OAUTH2_AUTHORIZE_URL', '')
    _OAUTH_ACCESS_TOKEN_URL = os.environ.get('OAUTH2_TOKEN_URL', '')

class GenericLoginHandler(OAuthLoginHandler, GenericEnvMixin):
    pass


class GenericOAuthenticator(OAuthenticator):

    login_service = "GenericOAuth2"

    login_handler = GenericLoginHandler

    userdata_url = Unicode(
        os.environ.get('OAUTH2_USERDATA_URL', ''),
        config=True,
        help="Userdata url to get user data login information"
    )

    username_key = Unicode(
        os.environ.get('OAUTH2_USERNAME_KEY', 'user_name'),
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
        
        config = {
            'proxy_host': 'proxy.pal.sap.corp',
            'proxy_port': 8080
          }
    
        AsyncHTTPClient.configure(
        "tornado.curl_httpclient.CurlAsyncHTTPClient")
    
        http_client = AsyncHTTPClient()

        params = dict(
            redirect_uri=self.get_callback_url(handler),
            code=code,
            grant_type='authorization_code'
        )

        url = url_concat(self.token_url, params)
        
        b64key = base64.b64encode(
            bytes(
                "{}:{}".format(self.client_id, self.client_secret),
                "utf8"
            )
         )
        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "Basic {}".format(b64key.decode("utf8"))
        }

        req = HTTPRequest(url,
                          method="POST",
                          headers=headers,
                          body=''  # Body is required for a POST...
                          )

        resp = yield http_client.fetch(req, **config)

        resp_json = json.loads(resp.body.decode('utf8', 'replace'))
        
        access_token = resp_json['access_token']
        token_type = resp_json['token_type']
        # Determine who the logged in user is
        headers = {
            "Accept": "application/json",
            "User-Agent": "JupyterHub",
            "Authorization": "{} {}".format(token_type, access_token)
        }
    
        url = url_concat(self.userdata_url, self.userdata_params)

        req = HTTPRequest(url,
                          method="GET",
                          headers=headers
                          )
        resp = yield http_client.fetch(req)
        resp_json = json.loads(resp.body.decode('utf8', 'replace'))

        if resp_json.get(self.username_key):
            return resp_json[self.username_key]


class LocalGenericOAuthenticator(LocalAuthenticator, GenericOAuthenticator):

    """A version that mixes in local system user creation"""
    pass
