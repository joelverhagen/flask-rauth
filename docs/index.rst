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
transfering Twitter password, for example. *This is a good thing!*

As mentioned before, Flask-Rauth supports the following protocols as a
consumer:

- OAuth 2.0 (`2.0 spec <http://tools.ietf.org/html/draft-ietf-oauth-v2-31>`_)
- OAuth 1.0a (`1.0a spec <http://oauth.net/core/1.0a/>`_)
- Ofly (i.e.
  `Shutterfly <http://www.shutterfly.com/documentation/start.sfly>`_)

Tutorial
--------

This tutorial should be able to help you get started with using OAuth 2.0 or
OAuth 1.0a with your Flask application. If you want to use Ofly (Shutterfly),
then take a look at :ref:`the example <ofly-example-label>` below.

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
"Joel's Awesome Flask App wants accesss to your Twitter information."

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
also require you to specify one or more static `redirect_uri` values. These
values form a whitelist of URLs that a user can be redirected to after
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

The `authorize_url` and `access_token_url` parameters are specific to the 
endpoint you are working with.

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

The `request_token_url`, `authorize_url`, and `access_token_url` parameters are
specific to the endpoint you are working with. Notice the additional
`request_token_url` parameter, compared to `OAuth 2.0`_.

See `Both Protocols`_ for information about the other keys.

Both Protocols
''''''''''''''

The `base_url` is **optional**, but can be provided so that
:ref:`making requests <making-request-label>` is a bit easier. The `name`
parameter is very important! This value will be used to determine the Flask
configuration keys that contain the associated **consumer key** and **private
key**.

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
in one place. One use-case is if you would like a seperate consumer key and
secret for a development vs. testing vs. production environment. 

.. code-block:: python
    :emphasize-lines: 6-7,9-10

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

Or, you can simply let Flask-Rauth use Flask's super-useful `current_app` to
get the currently active Flask application object, and look for the consumer
key and secret in its configuration.

Whether or not you call ``init_app``, the `name` parameter you pass to the
service object's constructor is extremely important. When Flask-Rauth is
looking for a consumer key or consumer secret, the name is uppercased (using
``name.upper()``) and appended with ``_CONSUMER_KEY`` and ``_CONSUMER_SECRET``,
respectively.

When initializing the service object
''''''''''''''''''''''''''''''''''''

Alternatively, you can pass the consumer key and consumer secret when
initializing your service object.

.. code-block:: python

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
``http://test.example.com/github/authorized`` and
``http://www.example.com/github/authorized``), you may be forced to use a
different consumer key and secret for each environment.

.. _callback-label:

Set a callback URL
~~~~~~~~~~~~~~~~~~

.. _making-request-label:

Making requests
~~~~~~~~~~~~~~~

Full Examples
-------------

OAuth 2.0 Example
~~~~~~~~~~~~~~~~~

OAuth 1.0a Example
~~~~~~~~~~~~~~~~~~

.. _ofly-example-label:

Ofly Example
~~~~~~~~~~~~

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

Helper Classes
~~~~~~~~~~~~~~

.. autoclass:: RauthResponse
   :members:

.. autoclass:: RauthServiceMixin
   :members:
   :exclude-members: consumer_secret_setter, consumer_key_setter

Exceptions and Functions
~~~~~~~~~~~~~~~~~~~~~~~~

.. autoexception:: RauthException

.. autofunction:: get_etree

.. autofunction:: parse_response

