from flask_appbuilder.security.views import AuthDBView
from flask_appbuilder import expose
from flask_login import login_user
from flask import request, redirect, session
import superset
from superset import app
from superset.security.manager import SupersetSecurityManager

import firebase_admin
from firebase_admin import auth
from firebase_admin import credentials
from firebase_admin import db

def validate_token(token):
    try:
        decoded_token = auth.verify_id_token(token)
        return decoded_token['uid']
    except Exception as e:
        print(e)
        return None

def get_user_data(uid):
    user_ref = db.reference('/usuarios/{}'.format(uid))
    user_data = user_ref.get()
    if user_data is not None and 'organizacion' not in user_data:
        user_data['organizacion'] = 'Sin organizacion'
    return user_data


class CustomAuthDBView(AuthDBView):
    login_template = 'appbuilder/general/security/login_db.html'
    @expose('/login/', methods=['GET', 'POST'])
    def login(self):
        if superset.app.config.get('TOKEN_LOGIN') is False:
            return super(CustomAuthDBView, self).login()

        token = request.values.get('token')
        if token is None:
            #return super(CustomAuthDBView, self).login()
            return "Token missing"

        try:
            cred = credentials.Certificate(superset.app.config.get('FIREBASE_SERVICE_ACCOUNT_FILE'))
            firebase_admin.initialize_app(cred)
        except ValueError as e:
            print(e)
        
        uid = validate_token(token)
        if uid is None:
            return "Invalid token"
        user_data = get_user_data(uid)
        if user_data is None:
            return "Invalid user"

        user = self.appbuilder.sm.find_user(
            username=uid
        )

        if not user:
            user = self.appbuilder.sm.add_user(
                username=uid,
                first_name=user_data["nombre"],
                last_name=user_data["organizacion"],
                email=user_data["correo"],
                role=self.appbuilder.sm.find_role("Alpha"),
                password = "test"
            )
        
        if not user:
            #return super(CustomAuthDBView, self).login()
            return "User not found"

        login_user(user, remember=False)
        redirect_url = superset.app.config.get(
             'DEFAULT_WELCOME_DASHBOARD'
        )
        # with standalone = True, the menu panel is removed
        standalone = str(request.args.get('standalone'))

        return redirect(
            redirect_url
            + '?standalone='
            + standalone
        )


class CustomSecurityManager(SupersetSecurityManager):
    authdbview = CustomAuthDBView
    def __init__(self, appbuilder):
        super(CustomSecurityManager, self).__init__(appbuilder)
