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

def get_user_data(uid, fb_app):
    user_ref = db.reference('/usuarios/{}'.format(uid), app=fb_app)
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
            return super(CustomAuthDBView, self).login()

        cred = credentials.Certificate(superset.app.config.get('FIREBASE_SERVICE_ACCOUNT_FILE'))
        fb_url = superset.app.config.get('FIREBASE_DEFAULT_DATABASE_URL')
        try:
            fb_app = firebase_admin.get_app()
        except ValueError as e:
            fb_app = firebase_admin.initialize_app(cred, {'databaseURL': fb_url})
            print(e)
        
        uid = validate_token(token)
        if uid is None:
            return "Invalid token"
        user_data = get_user_data(uid, fb_app)
        if user_data is None:
            return "Invalid user"

        user = self.appbuilder.sm.find_user(
            email=user_data["correo"]
        )

        if not user:
            ## Default login window.
            return super(CustomAuthDBView, self).login()
            ## Code for signing in new users automatically
            # user = self.appbuilder.sm.add_user(
            #     username=uid,
            #     first_name=user_data["nombre"],
            #     last_name=user_data["organizacion"],
            #     email=user_data["correo"],
            #     role=self.appbuilder.sm.find_role("Alpha"),
            #     password = "test"
            # )

        login_user(user, remember=False)
        redirect_url = superset.app.config.get(
             'DEFAULT_WELCOME_DASHBOARD'
        )

        return redirect(redirect_url)


class CustomSecurityManager(SupersetSecurityManager):
    authdbview = CustomAuthDBView
    def __init__(self, appbuilder):
        super(CustomSecurityManager, self).__init__(appbuilder)
