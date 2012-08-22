Flask-Rauth
===========

.. contents::
   :local:

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

.. autoclass:: RauthOAuth2
   :members:

.. autoclass:: RauthOAuth1
   :members:

.. autoclass:: RauthOfly
   :members:

Other Classes
~~~~~~~~~~~~~

.. autoclass:: RauthResponse
   :members:

.. autoclass:: RauthServiceMixin
   :members:
   :exclude-members: consumer_secret_setter, consumer_key_setter

Stuff You Probably Won't Have To Touch
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. autoexception:: RauthException

.. autofunction:: get_etree

.. autofunction:: parse_response

