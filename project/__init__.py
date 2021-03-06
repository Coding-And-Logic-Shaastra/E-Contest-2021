from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

# init SQLAlchemy so we can use it later in our models
db = SQLAlchemy()

def create_app():
    app = Flask(__name__, template_folder='./templates', static_folder='./static')

    app.config['SECRET_KEY'] = 'HAVOCRULEZ'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    ENV = 'PROD'
    if ENV == 'dev' :
        app.config['FLASK_DEBUG'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://localhost/econtest2021'
    else :
        app.config['FLASK_DEBUG'] = False
        app.config['SQLALCHEMY_DATABASE_URI'] = 'postgres://fnejfxskupdctt:2371d6ae74c391eefc780c010d2b4f5b26005e9bb5de320b412cb7a9c5cb3227@ec2-3-222-11-129.compute-1.amazonaws.com:5432/dd97eicet6la39'

    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    from .class_orm import User

    @login_manager.user_loader
    def load_user(user_id):
        # since the user_id is just the primary key of our user table, use it in the query for the user
        return User.query.get(int(user_id))

    # blueprint for auth routes in our app
    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    # blueprint for non-auth parts of app
    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    return app