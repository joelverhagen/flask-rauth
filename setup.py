"""
Flask-Rauth
-----------

Adds OAuth 1.0/a, 2.0, and Ofly consumer support for Flask.

Links
`````

* `development version <http://github.com/joelverhagen/flask-rauth/zipball/master#egg=Flask-OAuth-dev>`_
* `rauth <https://github.com/litl/rauth>`_
"""
from setuptools import setup


setup(
    name='Flask-Rauth',
    version='0.2',
    url='https://github.com/joelverhagen/flask-rauth',
    license='BSD',
    author='Joel Verhagen',
    author_email='joel.verhagen@gmail.com',
    description='Adds OAuth 1.0/a, 2.0, and Ofly consumer support for Flask.',
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
