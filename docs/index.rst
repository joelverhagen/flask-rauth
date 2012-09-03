Flask-Rauth
===========

.. currentmodule:: flask.ext.rauth

Adds OAuth 1.0/a, 2.0, and Ofly consumer support for `Flask`__, using the
`rauth`__ library.

__ http://flask.pocoo.org/
__ http://rauth.readthedocs.org/en/latest/

Flask-Rauth is a fork of Armin Ronacher's `Flask-OAuth`__.

__ https://github.com/mitsuhiko/flask-oauth

.. contents::
   :local:
   :backlinks: none

Introduction
------------

Flask-Rauth is a Flask extensions that allows you to easily interact with OAuth
2.0, OAuth 1.0a, and Ofly enabled applications. Please note that Flask-Rauth is
meant to only provide *consumer* support. This means that Flask-Rauth will
allow users on your Flask website to sign in to external web services (i.e. the
`Twitter API <https://dev.twitter.com/docs/auth/oauth>`_, `Facebook Graph API
<https://developers.facebook.com/docs/guides/web/#login>`_, `GitHub
<http://developer.github.com/v3/oauth/>`_, etc).

Once a user has authenticated with the external service, your server back-end
execute calls on the external API on behalf of the user via a secure token
process. This means that your application never has to deal with securing and
transferring Twitter password, for example. *This is a good thing!*

As mentioned before, Flask-Rauth supports the following protocols as a
consumer:

- OAuth 2.0 (`2.0 spec <http://tools.ietf.org/html/draft-ietf-oauth-v2-31>`_)
- OAuth 1.0a (`1.0a spec <http://oauth.net/core/1.0a/>`_)
- Ofly (i.e.
  `Shutterfly <http://www.shutterfly.com/documentation/start.sfly>`_)

Tutorial
--------

This tutorial should be able to help you get started with using OAuth 2.0 or
OAuth 1.0a with your Flask application.

Sign up with the external service
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Note:** you can skip this section if you already have a consumer_key and
consumer_secret.

Many social networking websites have OAuth 1.0a or 2.0 capabilities. Find
the developer documentation for an OAuth endpoint, and follow the documentation
to get two important pieces of information: a **consumer key** and a **consumer
secret**. You, as the web developer, are the consumer. The consumer key and 
consumer secret uniquely identify your website when you interact with the
external web service.

.. _consumer-label:

Get a consumer key and secret
'''''''''''''''''''''''''''''

To get the consumer key and consumer secret, you normally need to create an
"app" entry using some developer interface. This normally includes providing
a name, description, website and other fluffy information so that when your
users authenticate into the external web service they see a message like
"Joel's Awesome Flask App wants access to your Twitter information."

For the lazy, here's a list of a few OAuth web services and their
interfaces to get a consumer key and consumer secret.

**Note:** you will need to log in with credentials for each respective web
service for you to get a consumer key and consumer secret.

- Facebook, `Apps`__
- GitHub, `Developer applications`__
- Google, `APIs Console`__
- LinkedIn, `List of Applications`__
- Twitter, `Apps`__

__ https://developers.facebook.com/apps
__ https://github.com/settings/applications
__ https://code.google.com/apis/console/
__ https://www.linkedin.com/secure/developer
__ https://dev.twitter.com/apps

.. _oauth2-note:

OAuth 2.0 Note
''''''''''''''

Most OAuth 2.0 web services not only require you to specify a name,
description, etc. to get a consumer key and consumer secret, but they
also require you to specify one or more static ``redirect_uri`` values. These
values form a white list of URLs that a user can be redirected to after
authentication. The value you set should match the :ref:`callback URL
<callback-label>`.

Determine the protocol
~~~~~~~~~~~~~~~~~~~~~~

Depending on the external web service you are using, you will need to use a
different Flask-Rauth class. In the developer documentation, there will be some
indication whether it uses OAuth 1.0a or OAuth 2.0. Use the table below to map
the protocol to a Flask-Rauth service class.

+------------+----------------+
| Protocol   | Class          |
+============+================+
| OAuth 1.0a | `RauthOAuth1`_ |
+------------+----------------+
| OAuth 2.0  | `RauthOAuth2`_ |
+------------+----------------+

Enough with the talk, let's look at some code!

Initialize the service object
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To get started, you will need to initialize a Flask-Rauth 
:ref:`service object <services-label>`.

.. _oauth2-init:

OAuth 2.0
'''''''''

Initialize a `RauthOAuth2`_ object.

.. code-block:: python

    github = RauthOAuth2(
        name='github',
        base_url='https://api.github.com/',
        authorize_url='https://github.com/login/oauth/authorize',
        access_token_url='https://github.com/login/oauth/access_token'
    )

The `authorize_url` and `access_token_url` parameters are
specific to the endpoint you are working with.

See `Both Protocols`_ for information about the other keys.

OAuth 1.0a
''''''''''

Initialize a `RauthOAuth1`_ object:

.. code-block:: python

    twitter = RauthOAuth1(
        name='twitter',
        base_url='https://api.twitter.com/1/',
        request_token_url='https://api.twitter.com/oauth/request_token',
        authorize_url='https://api.twitter.com/oauth/authorize',
        access_token_url='https://api.twitter.com/oauth/access_token'
    )

The `request_token_url`, `authorize_url`, and `access_token_url`
parameters are specific to the endpoint you are working with. Notice the
additional `request_token_url` parameter, compared to :ref:`OAuth 2.0
<oauth2-init>`.

See `Both Protocols`_ for information about the other keys.

Both Protocols
''''''''''''''

The `base_url` is **optional**, but can be provided so that
:ref:`making requests <making-request-label>` is a bit easier. The
`name` parameter is very important! This value will be used to
determine the Flask configuration keys that contain the associated **consumer
key** and **private key**.

Set the consumer key and secret
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Assuming you've gotten a :ref:`consumer key and secret <consumer-label>` from
the web service you are working with, you can provide them to your service
object in a couple different ways.

In your app config
''''''''''''''''''

**This is the recommended method**, since it works very well when using an
application factory to generate your Flask application object or when you may
have multiple sets of consumer keys and secrets and you want to keep them all
in one place. One use-case is if you would like a separate consumer key and
secret for a development vs. testing vs. production environment. 

.. code-block:: python
    :emphasize-lines: 6-7, 9-10

    # create your application object
    # ...

    # set config values
    app.config.update(
        GITHUB_CONSUMER_KEY='<GitHub consumer key>',
        GITHUB_CONSUMER_SECRET='<GitHub consumer secret>',

        TWITTER_CONSUMER_KEY='<Twitter consumer key>',
        TWITTER_CONSUMER_SECRET='<Twitter consumer secret>',

        # other keys
        SECRET_KEY='just a secret key, to confound the bad guys',
        DEBUG=True
        # ...
    )

This setup should beg the following question: *how does Flask-Rauth know about
these keys and secrets?*

Well, you can register the service object that you initialized above
as an extension with your app object, like this:

.. code-block:: python

    # github is the RauthOAuth2 object, from above
    github.init_app(app)

Or, you can simply let Flask-Rauth use Flask's super-useful ``current_app`` to
get the currently active Flask application object, and look for the consumer
key and secret in its configuration.

Whether or not you call :func:`init_app`, the `name` parameter you pass to the
service object's constructor is extremely important. When Flask-Rauth is
looking for a consumer key or consumer secret, the name is upper cased (using
``name.upper()``) and appended with ``_CONSUMER_KEY`` and ``_CONSUMER_SECRET``,
respectively.

When initializing the service object
''''''''''''''''''''''''''''''''''''

Alternatively, you can pass the consumer key and consumer secret when
initializing your service object.

.. code-block:: python
    :emphasize-lines: 6-7, 16-17

    github = RauthOAuth2(
        name='github',
        base_url='https://api.github.com/',
        authorize_url='https://github.com/login/oauth/authorize',
        access_token_url='https://github.com/login/oauth/access_token',
        consumer_key='<GitHub consumer key>',
        consumer_secret='<GitHub consumer secret>'
    )

    twitter = RauthOAuth1(
        name='twitter',
        base_url='https://api.twitter.com/1/',
        request_token_url='https://api.twitter.com/oauth/request_token',
        authorize_url='https://api.twitter.com/oauth/authorize'
        access_token_url='https://api.twitter.com/oauth/access_token',
        consumer_key='<Twitter consumer key>',
        consumer_secret='<Twitter consumer secret>'
    )

This works just fine for applications that never need to worry about different
keys for different running environments. However, :ref:`as mentioned above
<oauth2-note>`, OAuth 2.0 requires you to predefine an absolute URL of where
users can be redirected after authentication. If you have a test environment
and production environment with different callback URLs (i.e.
`http://test.example.com/github/authorized` and
`http://www.example.com/github/authorized`), you may be forced to use a
different consumer key and secret for each environment.

.. _callback-label:

Redirect the user
~~~~~~~~~~~~~~~~~

Now that you've initialized everything, it's time to hook the service object
up. Both OAuth 2.0 and OAuth 1.0a have a step where the user is redirected from
the consumer's website (your Flask web app) to the external web service (i.e.
GitHub, Twitter, etc) for user authentication. Not only does the user log in on
the external website, but they also choose whether your app is allowed to
access their information.

To kick off the authentication process, call the :func:`authorize` method on
your service object, which will return a Flask `redirect` response.

.. code-block:: python
    :emphasize-lines: 9

    # initialize the Flask application object
    # ...

    # initialize the GitHub OAuth 2.0 service
    # ...

    @app.route('/redirect')
    def redirect():
        return github.authorize(callback=url_for('authorized', _external=True))

    @app.route('/authorized')
    @github.authorized_handler
    def authorized(...):
        # handle authorization

.. _making-request-label:

For both OAuth 1.0a and 2.0, the `callback` parameter is required. This tells
OAuth server where to redirect the user after they have authenticated. If you
use :func:`url_for` to generate the URL, make sure to generate an absolute URL
using ``_external=True``.

For OAuth 2.0, this `callback` parameter is mapped to the `redirect_uri` passed
to the the external web service.

Handle the authorization response
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

So far, everything is (hopefully) pretty straightforward. When the user comes
back from the external web service (after authorization), things get a bit more
complex.

In the previous step, you set the `callback` parameter for :func:`authorize` to
be the absolute URL to a another route (in the example above, the route was
``/authorized``). This route will be hit by the user after authentication.

This is a special route marked by the :func:`authorized_handler` decorator.
This route will receive two parameters upon successful authorization:
a special `RauthResponse` object and the token required for making requests on
behalf of the authenticated user. If the first parameter is `None` or 
``access_denied``, the authorization step failed (see `Handle if the user
denies`_).

When you declare your authorized handler, the top of it should look a lot like
this:

.. code-block:: python

    @app.route('/authorized')
    @github.authorized_handler
    def authorized(response, access_token):
        # ...

As you can see, you're expecting the two parameters that are mentioned above.

OAuth 2.0
'''''''''

The second parameter will be an `access_token`. This is a single secret string
used as a password, specific to your application, to make requests on behalf of
your user. The string can have any length, so if you're storing it in a
database, use a `Text` data type (unless you're very sure of the size, in which
case you can get by with a CHAR/VARCHAR).

If you're working with SQLAlchemy and declarative models (i.e.
`Flask-SQLAlchemy`__), you're code might look a bit like this:

__ http://packages.python.org/Flask-SQLAlchemy/

.. code-block:: python

    @app.route('/authorized')
    @github.authorized_handler
    def authorized(resp, access_token):
        # save the access token to the database
        current_user.access_token = access_token
        db.session.commit()

        return redirect(url_for('index'))

OAuth 1.0a
''''''''''

The second parameter will be an `oauth_token`. This is different from OAuth 2.0
because the token is actually a 2-tuple of an `oauth_token` and
`oauth_token_secret`. Both of these are strings of any length and BOTH are used
when making external web service calls on behalf of the user.

If you're working with SQLAlchemy and declarative models (i.e.
`Flask-SQLAlchemy`__), you're code might look a bit like this:

__ http://packages.python.org/Flask-SQLAlchemy/

.. code-block:: python

    @app.route('/authorized')
    @linkedin.authorized_handler
    def authorized(resp, oauth_token):
        # save the OAuth token to the database
        current_user.oauth_token = oauth_token[0]
        current_user.oauth_token_secret = oauth_token[1]
        db.session.commit()

        return redirect(url_for('index'))

Handle if the user denies
~~~~~~~~~~~~~~~~~~~~~~~~~

If you've worked with OAuth before, you'll know that there's the possibility
that the user denies access to their information. 

OAuth 2.0
'''''''''

This case is clearly defined in the OAuth 2.0 spec. The `redirect_uri` will
have the query parameter ``error=access_denied`` added to it. 

With Flask-Rauth, all you need to do is check whether the first argument in
your `authorized_handler` is equal to the string ``access_denied``.

.. code-block:: python
    :emphasize-lines: 4-5

    @app.route('/authorized')
    @github.authorized_handler
    def authorized(resp, access_token):
        if resp == 'access_denied':
            return 'You denied access, meanie.'

        flash('You have been logged in to GitHub successfully.')
        session['access_token'] = access_token

        return redirect(url_for('index'))

OAuth 1.0a
''''''''''

OAuth 1.0a, however, does not clearly define what the server should do if a
user denies the consumer application's access to his or her information.
Naturally, there is no common consensus in practice and many web APIs do it
differently.

Most OAuth 1.0a-enabled web services either do not have a `Deny` button at all
(assuming the user will simply close the window or tab, thus cutting the OAuth
process short) or have the `Deny` button redirect the user to the home page
of the external web service. This makes life difficult for us consumers!

Since the functionality isn't standard, you pretty much have to try it for each
external web service that you want to work with. Whenever the first argument to
your authorized handler is `None`, then we pretty much have to assume that the
user denied access.

For example, LinkedIn's `new authorization flow`__ does not indicate at all
that the user denied access. They just redirect back to your `callback`
without an `oauth_verifier` (which is a token that Flask-Rauth uses to fetch
the OAuth token which can be used to make calls on behalf of the user).

__ https://developer.linkedin.com/blog/making-it-easier-you-develop-linkedin

.. code-block:: python
    :emphasize-lines: 5

    @app.route('/authorized')
    @linkedin.authorized_handler
    def authorized(resp, oauth_token):
        if resp is None:
            return 'You denied access, meanie.'

        flash('You have been logged in to Twitter successfully.')
        session['oauth_token'] = oauth_token

        return redirect(url_for('index'))

For every OAuth 1.0a endpoint that you hook up to, I *highly* recommend that
you check the query parameters after you deny access to see if there is any
explicit indication of the deny.

In Twitter's case, if the user denies access to their Twitter account, then
a "denied" query parameter will be tacked on the end of your callback. Thanks
Twitter!

.. code-block:: python
    :emphasize-lines: 5

    @app.route('/authorized')
    @twitter.authorized_handler
    def authorized(resp, oauth_token):
        # check for the Twitter-specific "access_denied" indicator
        if resp is None and 'denied' in request.args:
            return 'You denied access, meanie.'
        elif resp is None:
            return 'Hey developer, something unexpected happened.'

        flash('You have been logged in to Twitter successfully.')
        session['oauth_token'] = oauth_token

        return redirect(url_for('index'))

Make a request
~~~~~~~~~~~~~~

Now that you have a valid token, you can make requests on behalf of your user.
All you need to do is call the :func:`get`, :func:`post`, :func:`put`, or
:func:`delete` functions on your service object. The optional arguments for
each request are outlined in the `Rauth documention`__.

__ http://rauth.readthedocs.org/en/latest/#rauth.service.OAuth2Service.request

Every API call requires that you provide the token that you aquired during user
authorization. There are two ways to do this.

Explicitly, by passing the token
''''''''''''''''''''''''''''''''

You can pass the token as a keyword argument to one of the aforementioned
request functions. When using OAuth 2.0, use the keyword `access_token`.

.. code-block:: python

    # github is an OAuth 2.0 service object
    r = github.get('user', access_token=my_access_token)

When using OAuth 1.0a, use the keyword `oauth_token`.

.. code-block:: python

    # twitter is an OAuth 1.0a service object
    r = twitter.get('account/verify_credentials.json', oauth_token=token)

This method of passing a token is most useful when you have to use multiple
tokens at the same time (i.e. you are fetching repository information for more
than one authorized GitHub user in a single request).

Implicitly, by defining a token getter function
'''''''''''''''''''''''''''''''''''''''''''''''

If you would like to tightly associate a specific token source (i.e. database,
session, cookies) with each user, declaring a token getter is probably the
cleanest solution.

When using OAuth 2.0, return the `access_token` recieved after authorization.

.. code-block:: python

    # github is an OAuth 2.0 service object
    @github.tokengetter
    def get_github_token():
        return session.get('access_token')

When using OAuth 1.0a, return the 2-tuple `oauth_token` recieved after
authorization.

.. code-block:: python

    # twitter is an OAuth 1.0a service object
    @twitter.tokengetter
    def get_twitter_token():
        # g is Flask's global object
        user = g.user
        if user is not None:
            return user.oauth_token

If no access token is available, just return `None`.

After the request completes, a :ref:`RauthResponse <response-label>` object is
returned.

Examples
--------

Make sure to check out the `example` directory if you're still confused about
the API.

`Examples`__, easily viewable in the GitHub source browser.

__ https://github.com/joelverhagen/flask-rauth/tree/master/example

API Reference
-------------

.. module:: flask_rauth

.. _services-label:

Services
~~~~~~~~

RauthOAuth2
'''''''''''
.. autoclass:: RauthOAuth2
   :members:

RauthOAuth1
'''''''''''
.. autoclass:: RauthOAuth1
   :members:

RauthOfly
'''''''''
.. autoclass:: RauthOfly
   :members:

Helpers
~~~~~~~~~~~~~~

.. _response-label:

.. autoclass:: RauthResponse
   :members:

Internals
~~~~~~~~~

.. autoclass:: RauthServiceMixin
   :members:
   :exclude-members: consumer_secret_setter, consumer_key_setter

.. autoexception:: RauthException

.. autofunction:: get_etree

.. autofunction:: parse_response

