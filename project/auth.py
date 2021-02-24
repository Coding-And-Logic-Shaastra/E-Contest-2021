from flask import Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length, EqualTo
from .class_orm import User
from . import db
from datetime import datetime, timezone, timedelta

auth = Blueprint('auth', __name__)

class LoginForm(FlaskForm) :
	shaastraID = StringField('shaastraID',validators = [InputRequired(), Length(max = 25,message='Shaastra ID must be atmost 25 characters')])
	password = PasswordField('password',validators = [InputRequired(), Length(min = 6,max = 50,message="Password must be between 6 and 50 characters")])

class RegisterForm(FlaskForm) :
    shaastraID = StringField('shaastraID',validators = [InputRequired(), Length(max = 25,message='Shaastra ID must be atmost 25 characters')])
    password = PasswordField('password',validators = [InputRequired(), Length(min = 6,max = 50,message='Password must be between 6 and 50 characters')])
    confirm_password = PasswordField('confirm_password',validators = [InputRequired(), EqualTo('password', message='Passwords must match')])
    email = StringField('email',validators = [InputRequired(), Length(max = 50,message='Email must be atmost 50 characters')])
    name = StringField('name',validators = [InputRequired(), Length(min = 1,max = 50,message='Name must be between 1 and 50 characters')])


@auth.route('/login', methods=['GET', 'POST'])
def login():
    curr_time = datetime.now(timezone(timedelta(hours=5, minutes=30)))
    reqd_time = datetime(2021, 2, 25, 19, 30, 0, 0, timezone(timedelta(hours=5, minutes=30)))
    if(curr_time < reqd_time):
        return render_template('wait.html', datetime=reqd_time.strftime("%d/%m/%Y | %H:%M:%S"))

    if(current_user.is_authenticated):
        return redirect(url_for('main.contest'))

    form = LoginForm(request.form)

    if request.method == 'POST' and form.validate():
        shaastraID = request.form.get('shaastraID')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False

        user = User.query.filter_by(shaastraID=shaastraID).first()

        # check if the user actually exists
        # take the user-supplied password, hash it, and compare it to the hashed password in the database
        if not user or not check_password_hash(user.password, password):
            flash('Please check your login details and try again.')
            return redirect(url_for('auth.login')) # if the user doesn't exist or password is wrong, reload the page

        # if the above check passes, then we know the user has the right credentials
        login_user(user, remember=remember)
        return redirect(url_for('main.contest'))

    errors = list(form.errors.values())

    return render_template('login.html', form=form, errors = errors)


@auth.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)

    if request.method == 'POST' and form.validate():
        shaastraID = request.form.get('shaastraID')
        password = request.form.get('password')
        name = request.form.get('name')
        email = request.form.get('email')
        confirm_pwd = request.form.get('confirm_password')

        user = User.query.filter_by(shaastraID = shaastraID).first() # if this returns a user, then the Shaastra ID already exists in database

        if user: # if a user is found, we want to redirect back to register page so user can try again
            flash('SHAASTRA ID already exists')
            return redirect(url_for('auth.register'))


        # create a new user with the form data. Hash the password so the plaintext version isn't saved.
        new_user = User(shaastraID=shaastraID, email=email, name=name, password=generate_password_hash(password, method='sha256'))

        # add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('auth.login'))

    errors = list(form.errors.values())

    return render_template('register.html', form=form, errors = errors)


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('main.index'))