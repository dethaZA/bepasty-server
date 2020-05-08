from flask import request, session
from flask.views import MethodView
from flask import current_app

from ..utils.http import redirect_next_referrer, redirect_next
from ..utils.permissions import LOGGEDIN, PERMISSIONS, lookup_permissions
from ..utils.adldap import ADLDAPauth

class LoginView(MethodView):
    def post(self):
        if 'LDAPSERVER' in current_app.config.keys():
            ldapserver = current_app.config['LDAPSERVER']
            realm = current_app.config['LDAPREALM'] if 'LDAPREALM' in current_app.config.keys() else None
            base = current_app.config['LDAPBASE'] if 'LDAPBASE' in current_app.config.keys() else None
            auth = ADLDAPauth(ldapserver, realm=realm, base=base)

            username = request.form.get('username')
            password = request.form.get('password')
            print(auth.get_permissions())
            if auth.authenticate(username, password):
                    session[PERMISSIONS] = auth.get_permissions()
                    session[LOGGEDIN] = True
        else:
            token = request.form.get('token')
            if token is not None:
                permissions_for_token = lookup_permissions(token)
                if permissions_for_token is not None:
                    session[PERMISSIONS] = permissions_for_token
                    session[LOGGEDIN] = True
        return redirect_next_referrer('bepasty.index')

    def get(self):
        return redirect_next('bepasty.index')


class LogoutView(MethodView):
    def post(self):
        # note: remove all session entries that are not needed for logged-out
        # state (because the code has defaults for them if they are missing).
        # if the session is empty. flask will automatically remove the cookie.
        session.pop(LOGGEDIN, None)
        session.pop(PERMISSIONS, None)
        return redirect_next_referrer('bepasty.index')

    def get(self):
        return redirect_next('bepasty.index')
