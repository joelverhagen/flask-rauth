Flask-Rauth
===========

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

Identify an external service
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

**Note:** you can skip this section if you already have a consumer_key and
consumer_secret.

Many social networking websites have OAuth 1.0a or 2.0 capabilities. Find
the developer documentation for an OAuth endpoint, and follow the documentation
to get two important pieces of information: a **consumer key** and a **consumer
secret**. You, as the web developer, are the consumer. The consumer key and 
consumer secret uniquely identify your website when you interact with the
external web service.

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

OAuth 2.0 Note
''''''''''''''

Most OAuth 2.0 web services not only require you to specify a name,
description, etc. to get a consumer key and consumer secret, but they
also require you to specify one or more static `redirect_uri` values. These
values form a whitelist of URLs that a user can be redirected to after
authentication. The value you set should match the callback URL. See
`Set a callback URL`_.

Set a callback URL
~~~~~~~~~~~~~~~~~~

Examples
--------

OAuth 2.0
~~~~~~~~~

OAuth 1.0a
~~~~~~~~~~

Ofly (i.e. Shutterfly)
~~~~~~~~~~~~~~~~~~~~~~

API Reference
-------------

.. module:: flask_rauth

Services
~~~~~~~~

RauthOAuth2 - for OAuth 2.0
'''''''''''''''''''''''''''
.. autoclass:: RauthOAuth2
   :members:

RauthOAuth1 - for OAuth 1.0a
''''''''''''''''''''''''''''
.. autoclass:: RauthOAuth1
   :members:

RauthOfly - for Shutterfly
''''''''''''''''''''''''''
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

