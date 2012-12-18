from flask import Flask, redirect, url_for, session, Response
from flask.ext.rauth import RauthOAuth2

app = Flask(__name__)
# you can specify the consumer key and consumer secret in the application,
#   like this:
app.config.update(
    GOOGLE_CONSUMER_KEY='your_conumser_key',
    GOOGLE_CONSUMER_SECRET='your_conumser_secret',
    SECRET_KEY='just a secret key, to confound the bad guys',
    DEBUG=True
)

google = RauthOAuth2(
    name='google',
    base_url='https://www.googleapis.com/oauth2/v1/',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth'
)

# the Rauth service detects the consumer_key and consumer_secret using
#   `current_app`.

@app.route('/')
def index():
    access_token = session.get('access_token')
    if access_token is None:
        return redirect(url_for('login'))

    userinfo = google.get('userinfo', access_token=access_token)

    from pprint import pformat
    return Response(pformat(userinfo.content), mimetype='text/plain')


@app.route('/login')
def login():
    return google.authorize(
        callback=url_for('authorized', _external=True),
        scope='https://www.googleapis.com/auth/userinfo.profile')


@app.route('/authorized')
@google.authorized_handler()
def authorized(resp, access_token):
    if resp == 'access_denied':
        return 'You denied access, meanie. Click <a href="%s">here</a> to try again.' % (url_for('login'),)

    session['access_token'] = access_token

    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run()
