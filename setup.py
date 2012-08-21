"""
Flask-Rauth
-----------

Adds OAuth 1.0/a, 2.0, and Ofly support to Flask.

Links
`````

* `documentation <http://packages.python.org/Flask-OAuth>`_
* `development version
  <http://github.com/mitsuhiko/flask-oauth/zipball/master#egg=Flask-OAuth-dev>`_
"""
from setuptools import setup


setup(
    name='Flask-Rauth',
    version='0.1',
    url='https://bitbucket.org/knapcode/flask-rauth',
    license='BSD',
    author='Armin Ronacher',
    author_email='armin.ronacher@active-4.com',
    description='Adds OAuth 1.0/a, 2.0, and Ofly support support to Flask',
    long_description=__doc__,
    py_modules=['flask_rauth'],
    zip_safe=False,
    platforms='any',
    install_requires=[
        'Flask',
        'rauth'
    ],
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]
)
