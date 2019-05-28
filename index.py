import os
import sys
import time
from datetime import datetime, timedelta
import ldap3
from ldap3 import MODIFY_ADD, MODIFY_REPLACE, MODIFY_DELETE
from config import Config

from flask import (Flask, request, render_template, redirect, session,
                   make_response)

from urllib.parse import urlparse

from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils


app = Flask(__name__)
app.config.from_object(Config)

def init_saml_auth(req):
    auth = OneLogin_Saml2_Auth(req, custom_base_path=app.config['SAML_PATH'])
    return auth


def prepare_flask_request(request):
    # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
    url_data = urlparse(request.url)
    return {
        'https': 'on',
        'http_host': request.host,
        'server_port': url_data.port,
        'script_name': request.path,
        'get_data': request.args.copy(),
        # Uncomment if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
        # 'lowercase_urlencoding': True,
        'post_data': request.form.copy()
    }

def update_ldap_token(usrEmail):
    try:
        srv = ldap3.Server(app.config['LDAP_IP'])
        conn = ldap3.Connection(srv, app.config['LDAP_BIND_CN'], app.config['LDAP_BIND_PW'], auto_bind=True)
    except:
        msg_user = 'LDAP connection error:{0}'.format(sys.exc_info()[0])
        return msg_user

    search_filter = '(mail=' + usrEmail + ')'
    if conn.search(app.config['LDAP_SEARCH_DN'], search_filter):
        if len(conn.response) == 1:
            entry = conn.response[0]
            work_period = datetime.now() + timedelta(minutes=app.config['TOKEN_TTL_MIN'])
            ldap_timestamp = time.mktime(work_period.timetuple())
            try:
                if conn.modify(entry['dn'], {'homeDirectory': [(MODIFY_REPLACE, [ldap_timestamp])]}):
                    msg_user = 'Token updated, you have 10 mins to work!'
                else:
                    msg_user = 'Cannot update token:{0}'.format(conn.last_error)
            except:
                msg_user = 'LDAP update error:{0}'.format(sys.exc_info()[0])
        else:
            msg_user = 'Ambiguous search results, more than one entry is returned.'
    else:
        msg_user = 'Cannot find user account to update.'
    conn.unbind()
    return  msg_user

@app.route('/', methods=['GET', 'POST'])
def index():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    errors = []
    not_auth_warn = False
    success_slo = False
    attributes = False
    fname = False
    lname = False
    umessage = False
    paint_logout = False


    if 'sso' in request.args:
        return redirect(auth.login())
    elif 'sso2' in request.args:
        return_to = '%sattrs/' % request.host_url
        return redirect(auth.login(return_to))
    elif 'slo' in request.args:
        name_id = None
        session_index = None
        if 'samlNameId' in session:
            name_id = session['samlNameId']
        if 'samlSessionIndex' in session:
            session_index = session['samlSessionIndex']

        return redirect(auth.logout(name_id=name_id, session_index=session_index))
    elif 'acs' in request.args:
        auth.process_response()
        errors = auth.get_errors()
        not_auth_warn = not auth.is_authenticated()
        if len(errors) == 0:
            if auth.is_authenticated():
                session.permanent = True
                app.permanent_session_lifetime = timedelta(minutes=app.config['TOKEN_TTL_MIN'])
            session['samlUserdata'] = auth.get_attributes()
            session['first_name'] = auth.get_attribute('account_firstname')
            session['last_name'] = auth.get_attribute('account_lastname')
            session['samlNameId'] = auth.get_nameid()
            session['samlSessionIndex'] = auth.get_session_index()
            self_url = OneLogin_Saml2_Utils.get_self_url(req)
            if 'RelayState' in request.form and self_url != request.form['RelayState']:
                return redirect(auth.redirect_to(request.form['RelayState']))
    elif 'sls' in request.args:
        dscb = lambda: session.clear()
        url = auth.process_slo(delete_session_cb=dscb)
        errors = auth.get_errors()
        if len(errors) == 0:
            if url is not None:
                return redirect(url)
            else:
                success_slo = True

    if 'samlUserdata' in session:
        paint_logout = True
        if len(session['samlUserdata']) > 0:
            attributes = session['samlUserdata'].items()
            fname = session['first_name']
            lname = session['last_name']
            umessage = update_ldap_token(session['samlNameId'])

    return render_template(
        'index.html',
        errors=errors,
        not_auth_warn=not_auth_warn,
        success_slo=success_slo,
        attributes=attributes,
        f_name = fname,
        l_name = lname,
        u_message = umessage,
        paint_logout=paint_logout
    )


@app.route('/attrs/')
def attrs():
    paint_logout = False
    attributes = False

    if 'samlUserdata' in session:
        paint_logout = True
        if len(session['samlUserdata']) > 0:
            attributes = session['samlUserdata'].items()

    return render_template('attrs.html', paint_logout=paint_logout,
                           attributes=attributes)


@app.route('/metadata/')
def metadata():
    req = prepare_flask_request(request)
    auth = init_saml_auth(req)
    settings = auth.get_settings()
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)

    if len(errors) == 0:
        resp = make_response(metadata, 200)
        resp.headers['Content-Type'] = 'text/xml'
    else:
        resp = make_response(', '.join(errors), 500)
    return resp


if __name__ == "__main__":
    app.run(host='127.0.0.1', port=8000, debug=True)
