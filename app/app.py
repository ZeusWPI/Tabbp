import json

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

tab_engine = create_engine(app.config['TAB_DB_URL'], convert_unicode=True)
tab_metadata = MetaData(bind=tab_engine)


@app.route('/login')
def login():
    return zeus_login()


def zeus_login():
    return zeus.authorize(callback=url_for('authorized', _external=True))


@app.route('/tokens')
def tokens():
    tab_query_result = tab_engine.execute('select key from users where name = :1', [session['username']]).first()
    if tab_query_result is None:
        return "Tab user doesn't exist"
    tab_token = tab_query_result[0]
    if tab_token is None:
        return "Tab user does't have a token"

    data = {'username': session['username'], 'tab_token': tab_token}
    response = jsonify(data)
    response.set_cookie('X-Auth', json.dumps(data))
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
