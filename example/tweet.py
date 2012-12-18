'''
Instructions:

1. Make sure you have Flask, Flask-Rauth, and SQLAlchemy installed.

       $ pip install Flask Flask-Rauth SQLAlchemy

2. Open a Python shell in this directory and execute the following:

       $ python
       >>> from tweet import init_db
       >>> init_db()
       >>> exit()

   This will initialize the SQLite database.

3. Start the application.

       $ python tweet.py

4. Navigate your web browser to where this app is being served (localhost,
   by default).
'''
from flask import Flask, request, redirect, url_for, session, flash, g, render_template
from flask.ext.rauth import RauthOAuth1

from sqlalchemy import create_engine, Column, Integer, String, Text
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

# setup flask
app = Flask(__name__)
# you can specify the consumer key and consumer secret in the application,
#   like this:
app.config.update(
    TWITTER_CONSUMER_KEY='your_consumer_key',
    TWITTER_CONSUMER_SECRET='your_consumer_secret',
    SECRET_KEY='just a secret key, to confound the bad guys',
    DEBUG = True
)


# setup the twitter endpoint
twitter = RauthOAuth1(
    name='twitter',
    base_url='https://api.twitter.com/1/',
    request_token_url='https://api.twitter.com/oauth/request_token',
    access_token_url='https://api.twitter.com/oauth/access_token',
    authorize_url='https://api.twitter.com/oauth/authorize'
)

# this call simply initializes default an empty consumer key and secret in the app
#   config if none exist. 
# I've included it to match the "look" of Flask extensions
twitter.init_app(app)

# setup sqlalchemy
engine = create_engine('sqlite:////tmp/tweet.db')
db_session = scoped_session(sessionmaker(autocommit=False, autoflush=False, bind=engine))
Base = declarative_base()
Base.query = db_session.query_property()


def init_db():
    Base.metadata.create_all(bind=engine)


class User(Base):
    __tablename__ = 'users'
    id = Column('user_id', Integer, primary_key=True)
    name = Column(String(60))
    oauth_token = Column(Text)
    oauth_secret = Column(Text)

    def __init__(self, name):
        self.name = name


@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        g.user = User.query.get(session['user_id'])


@app.after_request
def after_request(response):
    db_session.remove()
    return response


@twitter.tokengetter
def get_twitter_token():
    '''
    This is used by the API to look for the auth token and secret that are used
    for Twitter API calls. If you don't want to store this in the database,
    consider putting it into the session instead.

    Since the Twitter API is OAuth 1.0a, the `tokengetter` must return a
    2-tuple: (oauth_token, oauth_secret).
    '''
    user = g.user
    if user is not None:
        return user.oauth_token, user.oauth_secret


@app.route('/')
def index():
    tweets = None
    if g.user is not None:
        resp = twitter.get('statuses/home_timeline.json')
        if resp.status == 200:
            tweets = resp.content
        else:
            flash('Unable to load tweets from Twitter. Maybe out of '
                  'API calls or Twitter is overloaded.')
    return render_template('index.html', tweets=tweets)


@app.route('/tweet', methods=['POST'])
def tweet():
    '''
    Calls the remote twitter API to create a new status update.
    '''
    if g.user is None:
        return redirect(url_for('login', next=request.url))
    status = request.form['tweet']
    if not status:
        return redirect(url_for('index'))
    resp = twitter.post('statuses/update.json', data={
        'status': status
    })
    if resp.status == 403:
        flash('Your tweet was too long.')
    elif resp.status == 401:
        flash('Authorization error with Twitter.')
    else:
        flash('Successfully tweeted your tweet (ID: #%s)' % resp.content['id'])
    return redirect(url_for('index'))


@app.route('/login')
def login():
    '''
    Calling into `authorize` will cause the OAuth 1.0a machinery to kick
    in. If all has worked out as expected or if the user denied access to
    his/her information, the remote application will redirect back to the callback URL
    provided.

    Int our case, the 'authorized/' route handles the interaction after the redirect.
    '''
    return twitter.authorize(callback=url_for('authorized',
        _external=True,
        next=request.args.get('next') or request.referrer or None))


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You were signed out')
    return redirect(request.referrer or url_for('index'))


@app.route('/authorized')
@twitter.authorized_handler()
def authorized(resp, oauth_token):
    '''
    Called after authorization. After this function finished handling,
    the tokengetter from above is used to retrieve the 2-tuple containing the
    oauth_token and oauth_token_secret.

    Because reauthorization often changes any previous
    oauth_token/oauth_token_secret values, then we must update them in the
    database.

    If the application redirected back after denying, the `resp` passed
    to the function will be `None`. Unfortunately, OAuth 1.0a (the version
    that Twitter, LinkedIn, etc use) does not specify exactly what should
    happen when the user denies access. In the case of Twitter, a query
    parameter `denied=(some hash)` is appended to the redirect URL.
    '''
    next_url = request.args.get('next') or url_for('index')

    # check for the Twitter-specific "access_denied" indicator
    if resp is None and 'denied' in request.args:
        flash(u'You denied the request to sign in.')
        return redirect(next_url)

    # pull out the nicely parsed response content.
    content = resp.content

    user = User.query.filter_by(name=content['screen_name']).first()

    # this if the first time signing in for this user
    if user is None:
        user = User(content['screen_name'])
        db_session.add(user)

    # we now update the oauth_token and oauth_token_secret
    # this involves destructuring the 2-tuple that is passed back from the
    #   Twitter API, so it can be easily stored in the SQL database
    user.oauth_token = oauth_token[0]
    user.oauth_secret = oauth_token[1]
    db_session.commit()

    session['user_id'] = user.id
    flash('You were signed in')
    return redirect(next_url)


if __name__ == '__main__':
    app.run()
