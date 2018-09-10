"""
Base classes for Custom Authenticator to use GitHub OAuth with JupyterHub

Most of the code c/o Kyle Kelley (@rgbkrk)
"""


import os

from tornado import gen, web

from jupyterhub.handlers import BaseHandler
from jupyterhub.auth import Authenticator
from jupyterhub.utils import url_path_join

from traitlets import Unicode, Bool


def guess_callback_uri(protocol, host, hub_server_url):
    return '{proto}://{host}{path}'.format(
        proto=protocol,
        host=host,
        path=url_path_join(
            hub_server_url,
            'oauth_callback'
        )
    )


class OAuthLoginHandler(BaseHandler):
    """Base class for OAuth login handler

    Typically subclasses will need
    """
    scope = []

    def get(self):
        redirect_uri = self.authenticator.get_callback_url(self)
        self.log.info('oauth redirect: %r', redirect_uri)
        self.authorize_redirect(
            redirect_uri=redirect_uri,
            client_id=self.authenticator.client_id,
            scope=self.scope,
            response_type='code')


class OAuthCallbackHandler(BaseHandler):
    """Basic handler for OAuth callback. Calls authenticator to verify username."""
    @gen.coroutine
    def get(self):
        # TODO: Check if state argument needs to be checked
        username = yield self.authenticator.get_authenticated_user(self, None)
        self.log.info("UserName could be an issue")
        self.log.info("******")
        self.log.info(username)
        self.log.info("*****")
        if username:
            user = self.user_from_username(username)
            self.set_login_cookie(user)
            self.redirect(url_path_join(self.hub.server.base_url, 'home'))
        else:
            # todo: custom error page?
            raise web.HTTPError(403)


class OAuthenticator(Authenticator):
    """Base class for OAuthenticators

    Subclasses must override:

    login_service (string identifying the service provider)
    login_handler (likely a subclass of OAuthLoginHandler)
    authenticate (method takes one arg - the request handler handling the oauth callback)
    """

    login_service = 'override in subclass'
    oauth_callback_url = Unicode(
        os.getenv('OAUTH_CALLBACK_URL', ''),
        config=True,
        help="""Callback URL to use.
        Typically `https://{host}/hub/oauth_callback`"""
    )

    client_id_env = 'OAUTH_CLIENT_ID'
    client_id = Unicode(config=True)
    def _client_id_default(self):
        return os.getenv(self.client_id_env, '')

    client_secret_env = 'OAUTH_CLIENT_SECRET'
    client_secret = Unicode(config=True)
    def _client_secret_default(self):
        return os.getenv(self.client_secret_env, '')

    validate_server_cert_env = 'OAUTH_TLS_VERIFY'
    validate_server_cert = Bool(config=True)
    def _validate_server_cert_default(self):
        env_value = os.getenv(self.validate_server_cert_env, '')
        if env_value == '0':
            return False
        else:
            return True

    def login_url(self, base_url):
        return url_path_join(base_url, 'oauth_login')

    login_handler = "Specify login handler class in subclass"
    callback_handler = OAuthCallbackHandler
    
    def get_callback_url(self, handler=None):
        """Get my OAuth redirect URL
        
        Either from config or guess based on the current request.
        """
        if self.oauth_callback_url:
            return self.oauth_callback_url
        elif handler:
            return guess_callback_uri(
                handler.request.protocol,
                handler.request.host,
                handler.hub.server.base_url
            )
        else:
            raise ValueError("Specify callback oauth_callback_url or give me a handler to guess with")

    def get_handlers(self, app):
        return [
            (r'/oauth_login', self.login_handler),
            (r'/oauth_callback', self.callback_handler),
        ]

    @gen.coroutine
    def authenticate(self, handler, data=None):
        raise NotImplementedError()
