from flask import Flask, redirect, url_for, session, request, Response
from flask.ext.rauth import RauthOAuth2

app = Flask(__name__)
app.config.update(
    SECRET_KEY='just a secret key, to confound the bad guys',
    DEBUG=True
)

# you can specify your consumer key and consumer secret when constructing
#   the Rauth service, like this:
facebook = RauthOAuth2(
    name='facebook',
    base_url='https://graph.facebook.com/',
    access_token_url='https://graph.facebook.com/oauth/access_token',
    authorize_url='https://www.facebook.com/dialog/oauth',
    consumer_key='your_consumer_key',
    consumer_secret='your_consumer_secret'
)


@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/login')
def login():
    return facebook.authorize(callback=url_for('authorized',
        next=request.args.get('next') or request.referrer or None,
        _external=True))


@app.route('/login/authorized')
@facebook.authorized_handler()
def authorized(resp, access_token):
    if resp == 'access_denied':
        return 'You denied access, meanie. Click <a href="%s">here</a> to try again.' % (url_for('login'),)

    session['access_token'] = access_token

    me = facebook.get('me')
    
    from pprint import pformat
    return Response(pformat(me.content), mimetype='text/plain')


@facebook.tokengetter
def get_facebook_oauth_token():
    return session.get('access_token')


if __name__ == '__main__':
    app.run()
