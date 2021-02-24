from . import db
from flask_login import UserMixin

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer,primary_key = True)
    shaastraID = db.Column(db.String(25),nullable = False,unique = True)
    password = db.Column(db.String(100),nullable = False)
    name = db.Column(db.String(50),nullable = False)
    email = db.Column(db.String(50),nullable = False)

    def __init__(self, **kwargs) :
        super(User, self).__init__(**kwargs)