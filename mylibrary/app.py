import datetime
import re
from functools import wraps

import mysql.connector as connector
from flask import Flask, render_template, session, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required

from mysqldb import DBConnector

app = Flask(__name__)
application = app
app.config.from_pyfile('config.py')

db_connector = DBConnector(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth'
login_manager.login_message_category = 'warning'

def db_operation(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        connection = db_connector.connect()
        try:
            with connection.cursor(named_tuple=True, buffered=True) as cursor:
                result = func(cursor, *args, **kwargs)
                connection.commit()
        except Exception as e:
            connection.rollback()
            raise e
        finally:
            connection.close()
        return result
    return wrapper

class User(UserMixin):
    def __init__(self, user_id, user_login):
        self.id = user_id
        self.user_login = user_login

@login_manager.user_loader
def load_user(user_id):
    with db_connector.connect().cursor(named_tuple=True) as cursor:
        cursor.execute("SELECT id, login FROM users WHERE id = %s;", (user_id,))
        user = cursor.fetchone()
    if user is not None:
        return User(user.id, user.login)
    return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/auth', methods=['POST', 'GET'])
@db_operation
def auth(cursor):
    if request.method == 'POST':
        login = request.form['username']
        password = request.form['password']
        remember_me = request.form.get('remember_me', None) == 'on'

        cursor.execute(
            "SELECT id, login FROM users WHERE login = %s AND password_hash = SHA2(%s, 256)",
            (login, password)
        )
        user = cursor.fetchone()

        if user:
            flash('Авторизация прошла успешно', 'success')
            login_user(User(user.id, user.login), remember=remember_me)
            next_url = request.args.get('next', url_for('index'))
            return redirect(next_url)
        flash('Invalid username or password', 'danger')
    return render_template('auth.html')

@app.route('/register', methods=['POST', 'GET'])
@db_operation
def register(cursor):
    if request.method == 'POST':
        username = request.form['username']
        login = request.form['login']
        email = request.form['email']
        password = request.form['password']
        role_id = request.form['role']

        cursor.execute(
            "INSERT INTO users (username, login, password_hash, email, role_id) "
            "VALUES (%s, %s, SHA2(%s, 256), %s, %s)",
            (username, login, password, email, role_id)
        )
        flash('Регистрация прошла успешно!', 'success')
        return redirect(url_for('auth'))
    return render_template('register.html')

@app.route('/profile')
def profile():
    return render_template('profile.html')

@app.route('/book')
def book():
    return render_template('book.html')

@app.route('/admin/add_book')
def add_book():
    return render_template('add_book.html')

@app.route('/admin/users')
def users():
    return render_template('users.html')

@app.route('/admin/edit_user')
def edit_user():
    return render_template('edit_user.html')

if __name__ == '__main__':
    app.run(debug=True)
