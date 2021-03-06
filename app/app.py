import json
import urllib.parse
import re

from flask import Flask, redirect, url_for, session, jsonify, request
from flask_oauthlib.client import OAuth, OAuthException
from sqlalchemy import create_engine, MetaData

app = Flask(__name__)
from app import config


oauth = OAuth(app)
zeus = oauth.remote_app(
    'zeus',
    consumer_key=app.config['OAUTH_KEY'],
    consumer_secret=app.config['OAUTH_SECRET'],
    request_token_params={},
    base_url='https://adams.ugent.be/oauth/api/',
    access_token_method='POST',
    access_token_url='https://adams.ugent.be/oauth/oauth2/token/',
    authorize_url='https://adams.ugent.be/oauth/oauth2/authorize/'
)

tab_engine = create_engine(app.config['TAB_DB_URL'], convert_unicode=True, pool_pre_ping=True)
tab_metadata = MetaData(bind=tab_engine)

tap_engine = create_engine(app.config['TAP_DB_URL'], convert_unicode=True, pool_pre_ping=True)
tap_metadata = MetaData(bind=tap_engine)


@app.route('/login')
def login():
    return zeus_login()


def zeus_login():
    return zeus.authorize(callback=url_for('authorized', _external=True))


@app.route('/tokens')
def tokens():
    if 'username' not in session:
        return redirect(url_for("login"))

    # Look, I know this is bad
    # The reason why I did is, is that different databasedrivers (sqlite, mysql, ...)
    # have different ways to prepare SQL statements, and these are incompatible
    if not re.match(r'[a-zA-Z\-_0-9]+$', session['username']):
        return 'Username should only contain letters, numbers, - or _'
    with tab_engine.connect() as tab_connection, tap_engine.connect() as tap_connection:
        tab_query_result = tab_connection.execute("SELECT `key` FROM users WHERE name = '%s'" % session['username']).first()
        if tab_query_result is None:
            return "Tab user doesn't exist"
        tab_token = tab_query_result[0]
        if tab_token is None:
            return "Tab user does't have a token"

        tap_query_result = tap_connection.execute("SELECT `userkey` FROM users WHERE name = '%s'" % session['username']).first()
        if tap_query_result is None:
            return "Tap user doesn't exist"
        tap_token = tap_query_result[0]
        if tap_token is None:
            return "Tap user does't have a token"

    data = {'username': session['username'], 'tab_token': tab_token, 'tap_token': tap_token}
    response = jsonify(data)
    response.set_cookie('X-Auth', urllib.parse.quote_plus(json.dumps(data)))
    return response


@app.route('/login/zeus/authorized')
def authorized():
    resp = zeus.authorized_response()
    if resp is None:
        return 'Something went wrong: %s' % request.args['error']
    if isinstance(resp, OAuthException):
        return 'Access denied: %s' % resp.message + '<br>' + str(resp.data)

    session['zeus_token'] = (resp['access_token'], '')
    me = zeus.get('current_user/')
    username = me.data.get('username', '')
    session['username'] = username
    return redirect(url_for("tokens"))


@zeus.tokengetter
def get_zeus_oauth_token():
    return session.get('zeus_token')
