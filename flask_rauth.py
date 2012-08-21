# -*- coding: utf-8 -*-
"""
    flask_oauth
    ~~~~~~~~~~~

    Implements basic OAuth support for Flask.

    :copyright: (c) 2010 by Armin Ronacher.
    :license: BSD, see LICENSE for more details.
"""
from functools import wraps
from urlparse import urljoin
from flask import request, session, redirect, current_app
from werkzeug import parse_options_header
from rauth.service import OAuth2Service, OAuth1Service, OflyService, Response, parse_utf8_qsl

# specified by the OAuth 2.0 spec
# http://tools.ietf.org/html/draft-ietf-oauth-v2-31#section-4.1.4
ACCESS_DENIED = 'access_denied'

_etree = None
def get_etree():
    """Return an elementtree implementation.  Prefers lxml"""
    global _etree
    if _etree is None:
        try:
            from lxml import etree
            _etree = etree
        except ImportError:
            try:
                from xml.etree import cElementTree
                _etree = cElementTree
            except ImportError:
                try:
                    from xml.etree import ElementTree
                    _etree = ElementTree
                except ImportError:
                    pass
    return _etree

def parse_response(resp):
    if resp.json is not None:
        return resp.json

    ct, _ = parse_options_header(resp.headers.get('content-type'))

    if ct in ('application/xml', 'text/xml'):
        etree = get_etree()
        if etree is not None:
            return etree.fromstring(resp.content)

    if ct in ('application/atom+xml', 'application/rss+xml'):
        try:
            import feedparser
            return feedparser.parse(resp.content)
        except:
            pass

    if isinstance(resp.content, basestring):
        return parse_utf8_qsl(resp.content)

    return resp.content

class RauthException(RuntimeError):
    """Raised if authorization fails for some reason."""
    message = None

    def __init__(self, message, response=None):
        # a helpful error message for debugging
        self.message = message
        
        # if available, the parsed response from the remote API that can be used to pointpoint the error.
        self.response = response

    def __str__(self):
        return self.message.encode('utf-8')

    def __unicode__(self):
        return self.message

class RauthResponse(Response):
    def __init__(self, resp):
        # the original response
        self.response = resp.response

        self._cached_content = None

    @property
    def content(self):
        if self._cached_content is None:
            # the parsed content from the server
            self._cached_content = parse_response(self.response)
        return self._cached_content

    @property
    def status(self):
        """The status code of the response."""
        return self.resp.status_code

    @property
    def content_type(self):
        """The Content-Type of the response."""
        return self.resp.headers.get('content-type')

class RauthServiceMixin(object):
    def __init__(self, app, base_url):
        self.app = app
        if app is not None:
            self.init_app(app)

        self.base_url = base_url
        self.tokengetter_f = None

    def init_app(self, app):
        # the name attribute will be set by a rauth service
        app.config.setdefault(self._consumer_key_config())
        app.config.setdefault(self._consumer_secret_config())

    def tokengetter(self, f):
        self.tokengetter_f = f
        return f

    def _expand_url(self, url):
        # prepend the base base_url, if we have it
        if self.base_url is not None:
            url = urljoin(self.base_url, url)
        return url

    def _session_key(self, suffix):
        return '%s_%s_%s' % (self.name, self.__class__.__name__, suffix)

    @property
    def consumer_key(self):
        if self.static_consumer_key is not None:
            # if a consumer key was provided in the constructor, default to that
            return self.static_consumer_key
        elif self.app is not None and self._consumer_key_config() in self.app.config:
            # if an app was provided in the constructor, search its config first
            return self.app.config[self._consumer_key_config()]

        # otherwise, search in the current_app config
        return current_app.config.get(self._consumer_key_config(), None)

    @consumer_key.setter
    def consumer_key_setter(self, consumer_key):
        self.static_consumer_key = consumer_key

    @property
    def consumer_secret(self):
        if self.static_consumer_secret is not None:
            # if a consumer secret was provided in the constructor, default to that
            return self.static_consumer_secret
        elif self.app is not None and self._consumer_secret_config() in self.app.config:
            # if an app was provided in the constructor, search its config first
            return self.app.config[self._consumer_secret_config()]

        # otherwise, search in the current_app config
        return current_app.config.get(self._consumer_secret_config(), None)

    @consumer_secret.setter
    def consumer_secret_setter(self, consumer_secret):
        self.static_consumer_secret = consumer_secret

    def _consumer_key_config(self):
        return '%s_CONSUMER_KEY' % (self.name.upper(),)

    def _consumer_secret_config(self):
        return '%s_CONSUMER_SECRET' % (self.name.upper(),)

class RauthOAuth2(OAuth2Service, RauthServiceMixin):
    def __init__(self, app=None, base_url=None, consumer_key=None, consumer_secret=None, **kwargs):
        OAuth2Service.__init__(self, consumer_key=consumer_key, consumer_secret=consumer_secret, **kwargs)
        RauthServiceMixin.__init__(self, app=app, base_url=base_url)

    def authorize(self, **authorize_params):
        # OAuth 2.0 requires a redirect_uri value
        assert 'redirect_uri' in authorize_params, 'The "redirect_uri" must be provided when generating the authorize URL'

        # save the redirect_uri in the session
        session[self._session_key('redirect_uri')] = authorize_params['redirect_uri']

        return redirect(self.get_authorize_url(**authorize_params))

    def authorized_handler(self, f):
        @wraps(f)
        def decorated(*args, **kwargs):
            resp = access_token = None
            if 'error' in request.args:
                if  request.args['error'] == ACCESS_DENIED:
                    resp = ACCESS_DENIED
                else:
                    raise RauthException('An unexpected error occurred during authorization: error: "%s", error_description: "%s", error_uri: "%s"' % (request.args.get('error'), request.args.get('error_description'), request.args.get('error_uri')))
            elif 'error' not in request.args and 'code' not in request.args:
                # if this happens, there's probably a problem with the provider
                raise RauthException('No error or code provided in the authorization grant')
            else:
                resp = self.get_access_token(data={
                    'code': request.args['code'],
                    'redirect_uri': session.pop(self._session_key('redirect_uri'), None)
                })
                access_token = resp.content['access_token']

            return f(*((resp, access_token) + args), **kwargs)
        return decorated

    def request(self, method, url, access_token=None, **kwargs):
        url = self._expand_url(url)

        if access_token is None and self.tokengetter_f is not None:
            access_token = self.tokengetter_f()

        # add in the access_token
        if 'params' not in kwargs:
            kwargs['params'] = {'access_token': access_token}
        elif 'access_token' not in kwargs['params']:
            # TODO: handle if the user sends bytes -> properly append 'access_token'
            kwargs['params']['access_token'] = access_token

        # call the parent implementation
        return RauthResponse(OAuth2Service.request(self, method, url, **kwargs))

class RauthOAuth1(OAuth1Service, RauthServiceMixin):
    def __init__(self, app=None, base_url=None, consumer_key=None, consumer_secret=None, **kwargs):
        OAuth1Service.__init__(self, consumer_key=consumer_key, consumer_secret=consumer_secret, **kwargs)
        RauthServiceMixin.__init__(self, app=app, base_url=base_url)

    def authorize(self, **request_params):
        # OAuth 1.0/a web authentication requires a oauth_callback value
        assert 'oauth_callback' in request_params, 'The "oauth_callback" must be provided when generating the authorize URL'

        # fetch the request_token (token and secret 2-tuple) and convert it to a dict
        request_token = self.get_request_token(oauth_callback=request_params['oauth_callback'])
        request_token = {'request_token': request_token[0], 'request_token_secret': request_token[1]}

        # save the request_token in the session
        session[self._session_key('request_token')] = request_token

        # pass the token and any user-provided parameters
        return redirect(self.get_authorize_url(request_token['request_token']))

    def authorized_handler(self, f):
        @wraps(f)
        def decorated(*args, **kwargs):
            resp = oauth_token = None
            if 'oauth_verifier' in request.args:
                resp = self.get_access_token(data={
                    'oauth_verifier': request.args['oauth_verifier']
                }, **session.pop(self._session_key('request_token'), {}))
                oauth_token = (resp.content['oauth_token'], resp.content['oauth_token_secret'])

            return f(*((resp, oauth_token) + args), **kwargs)
        return decorated

    def request(self, method, url, oauth_token=None, **kwargs):
        url = self._expand_url(url)

        if oauth_token is None and self.tokengetter_f is not None:
            oauth_token = self.tokengetter_f()

        # take apart the 2-tuple
        if oauth_token is not None:
            oauth_token, oauth_token_secret = oauth_token

        # call the parent implementation
        return RauthResponse(OAuth1Service.request(self, method, url, access_token=oauth_token, access_token_secret=oauth_token_secret, **kwargs))

class RauthOfly(OflyService, RauthServiceMixin):
    def __init__(self, app=None, base_url=None, consumer_key=None, consumer_secret=None, **kwargs):
        OflyService.__init__(self, consumer_key=consumer_key, consumer_secret=consumer_secret, **kwargs)
        RauthServiceMixin.__init__(self, app=app, base_url=base_url)

    def authorize(self, **authorize_params):
        # Ofly web authentication (== "app authentication" == "seamless sign-in") requires a redirect_uri value
        assert 'redirect_uri' in authorize_params, 'The "redirect_uri" must be provided when generating the authorize URL'

        # pass the token and any user-provided parameters
        return redirect(self.get_authorize_url(**authorize_params))

    def authorized_handler(self, f):
        @wraps(f)
        def decorated(*args, **kwargs):
            resp = oflyUserid = None
            if 'oflyUserid' not in request.args:
                raise RauthException('No oflyUserid provided in the authorization grant')
            elif request.args['oflyUserid'] == 'no-grant':
                resp = ACCESS_DENIED
            else:
                resp = {
                    'oflyUserid': request.args.get('oflyUserid'),
                    'oflyAppId': request.args.get('oflyAppId'),
                    'oflyUserEmail': request.args.get('oflyUserEmail')
                }
                oflyUserid = request.args['oflyUserid']

            return f(*((resp, oflyUserid) + args), **kwargs)
        return decorated

    def request(self, method, url, oflyUserid=None, **kwargs):
        url = self._expand_url(url)

        if oflyUserid is None and self.tokengetter_f is not None:
            oflyUserid = self.tokengetter_f()

        # add in the access_token
        if 'params' not in kwargs:
            kwargs['params'] = {'oflyUserid': oflyUserid}
        elif 'oflyUserid' not in kwargs['params']:
            # TODO: handle if the user sends bytes -> properly append 'oflyUserid'
            kwargs['params']['oflyUserid'] = oflyUserid

        # call the parent implementation
        return RauthResponse(OflyService.request(self, method, url, **kwargs))
