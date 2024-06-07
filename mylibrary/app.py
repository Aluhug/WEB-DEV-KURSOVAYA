import os
import datetime
import re
from functools import wraps

import mysql.connector as connector
from flask import Flask, render_template, session, request, redirect, url_for, flash, abort
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.utils import secure_filename
from mysqldb import DBConnector

app = Flask(__name__)
application = app
app.config.from_pyfile('config.py')
app.config['UPLOAD_FOLDER'] = app.config.get('UPLOAD_FOLDER', 'static/images')
app.config['DEFAULT_COVER_IMAGE'] = app.config.get('DEFAULT_COVER_IMAGE', 'static/images/default_cover.jpg')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

db_connector = DBConnector(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth'
login_manager.login_message_category = 'warning'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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
            print(f"Error in {func.__name__}: {e}")  # Добавление отладочной информации
            raise e
        return result
    return wrapper

class User(UserMixin):
    def __init__(self, user_id, user_login, role_id):
        self.id = user_id
        self.user_login = user_login
        self.role_id = role_id

@login_manager.user_loader
def load_user(user_id):
    with db_connector.connect().cursor(named_tuple=True) as cursor:
        cursor.execute("SELECT id, login, role_id FROM users WHERE id = %s;", (user_id,))
        user = cursor.fetchone()
    if user is not None:
        return User(user.id, user.login, user.role_id)
    return None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role_id != 2:
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin/add_book', methods=['GET', 'POST'])
@admin_required
@db_operation
def add_book(cursor):
    if request.method == 'POST':
        title = request.form['title']
        author = request.form['author']
        genre = request.form['genre']
        description = request.form['description']
        file = request.files['cover_image']
        cover_image = app.config['DEFAULT_COVER_IMAGE']

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            cover_image = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        
        cursor.execute("""
            INSERT INTO books (title, author_id, genre_id, description, cover_image) 
            VALUES (%s, (SELECT id FROM authors WHERE CONCAT(first_name, ' ', last_name) = %s), (SELECT id FROM genres WHERE name = %s), %s, %s)
        """, (title, author, genre, description, cover_image))
        flash('Книга успешно добавлена', 'success')
        return redirect(url_for('books'))
    return render_template('add_book.html')

@app.route('/admin/users')
@admin_required
@db_operation
def users(cursor):
    try:
        cursor.execute("SELECT id, username, login, email, password_hash, role_id FROM users")
        users = cursor.fetchall()
        return render_template('users.html', users=users)
    except Exception as e:
        print(f"Error in users route: {e}")
        abort(500)

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@admin_required
@db_operation
def edit_user(cursor, user_id):
    try:
        cursor.execute("SELECT id, username, login, email, role_id FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        if request.method == 'POST':
            username = request.form['username']
            login = request.form['login']
            email = request.form['email']
            role_id = request.form['role']
            cursor.execute("UPDATE users SET username = %s, login = %s, email = %s, role_id = %s WHERE id = %s",
                           (username, login, email, role_id, user_id))
            flash('Профиль успешно обновлен', 'success')
            return redirect(url_for('users'))
        return render_template('edit_user.html', user=user)
    except Exception as e:
        print(f"Error in edit_user route: {e}")
        abort(500)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/auth', methods=['POST', 'GET'])
@db_operation
def auth(cursor):
    try:
        if request.method == 'POST':
            login = request.form['username']
            password = request.form['password']
            remember_me = request.form.get('remember_me', None) == 'on'

            cursor.execute(
                "SELECT id, login, role_id FROM users WHERE login = %s AND password_hash = SHA2(%s, 256)",
                (login, password)
            )
            user = cursor.fetchone()

            if user:
                flash('Авторизация прошла успешно', 'success')
                login_user(User(user.id, user.login, user.role_id), remember=remember_me)
                next_url = request.args.get('next', url_for('index'))
                return redirect(next_url)
            flash('Invalid username or password', 'danger')
        return render_template('auth.html')
    except Exception as e:
        print(f"Error in auth route: {e}")
        abort(500)

@app.route('/register', methods=['POST', 'GET'])
@db_operation
def register(cursor):
    try:
        if request.method == 'POST':
            username = request.form['username']
            login = request.form['login']
            email = request.form['email']
            password = request.form['password']
            confirm_password = request.form['confirm_password']
            role_id = request.form['role']

            if not re.match(r'^[a-zA-Zа-яА-ЯёЁ]{2,20}$', username):
                flash('Username должен содержать только буквы кириллицы и латиницы длиной от 2 до 20 символов', 'danger')
                return render_template('register.html', username=username, login=login, email=email, role_id=role_id)
            
            if not re.match(r'^[a-zA-Zа-яА-ЯёЁ0-9_]{3,20}$', login):
                flash('Login должен содержать только буквы, цифры и символы "_" и быть длиной от 3 до 20 символов.', 'danger')
                return render_template('register.html', username=username, login=login, email=email, role_id=role_id)

            if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
                flash('Email некорректен.', 'danger')
                return render_template('register.html', username=username, login=login, email=email, role_id=role_id)

            if password != confirm_password:
                flash('Пароли не совпадают', 'danger')
                return render_template('register.html', username=username, login=login, email=email, role_id=role_id)

            if not re.match(r'^[a-zA-Zа-яА-ЯёЁ0-9~!@#$%^&*_+()[\]{}<>\\/|"\'.,:;]{8,}$', password):
                flash('Пароль должен быть минимум 8 символов длиной и содержать буквы, цифры и специальные символы.', 'danger')
                return render_template('register.html', username=username, login=login, email=email, role_id=role_id)

            cursor.execute(
                "INSERT INTO users (username, login, password_hash, email, role_id) "
                "VALUES (%s, %s, SHA2(%s, 256), %s, %s)",
                (username, login, password, email, role_id)
            )
            cursor.execute("SELECT id FROM users WHERE login = %s", (login,))
            user = cursor.fetchone()
            login_user(User(user.id, login, role_id))
            flash('Регистрация прошла успешно!', 'success')
            return redirect(url_for('books'))
        return render_template('register.html')
    except Exception as e:
        print(f"Error in register route: {e}")
        abort(500)

@app.route('/profile')
@login_required
@db_operation
def profile(cursor):
    try:
        user_id = current_user.id
        cursor.execute("""
            SELECT username, login FROM users WHERE id = %s
        """, (user_id,))
        user = cursor.fetchone()

        cursor.execute("""
            SELECT books.title, authors.first_name AS author_first_name, authors.last_name AS author_last_name 
            FROM reservations
            JOIN books ON reservations.book_id = books.id
            JOIN authors ON books.author_id = authors.id
            WHERE reservations.user_id = %s AND reservations.status = TRUE
        """, (user_id,))
        reserved_books = cursor.fetchall()
        cursor.execute("""
            SELECT books.title, authors.first_name AS author_first_name, authors.last_name AS author_last_name 
            FROM reservations
            JOIN books ON reservations.book_id = books.id
            JOIN authors ON books.author_id = authors.id
            WHERE reservations.user_id = %s AND reservations.status = TRUE
        """, (user_id,))
        reading_books = cursor.fetchall()

        return render_template('profile.html', user=user, reserved_books=reserved_books, reading_books=reading_books)
    except Exception as e:
        print(f"Error in profile route: {e}")
        abort(500)

@app.route('/books')
@login_required
@db_operation
def books(cursor):
    try:
        cursor.execute("""
            SELECT books.id, books.title, CONCAT(authors.first_name, ' ', authors.last_name) AS author, genres.name AS genre, books.description, COALESCE(books.cover_image, %s) AS cover_image 
            FROM books
            JOIN authors ON books.author_id = authors.id
            JOIN genres ON books.genre_id = genres.id
        """, (app.config['DEFAULT_COVER_IMAGE'],))
        books = cursor.fetchall()
        print(f"Books fetched: {books}")  # Отладочная информация
        return render_template('books.html', books=books)
    except Exception as e:
        print(f"Error in books route: {e}")
        abort(500)


@app.route('/book/<int:book_id>')
@login_required
@db_operation
def book_detail(cursor, book_id):
    try:
        cursor.execute("""
            SELECT books.title, CONCAT(authors.first_name, ' ', authors.last_name) AS author, genres.name AS genre, books.description, books.cover_image 
            FROM books
            JOIN authors ON books.author_id = authors.id
            JOIN genres ON books.genre_id = genres.id
            WHERE books.id = %s
        """, (book_id,))
        book = cursor.fetchone()
        if book is None:
            abort(404)
        return render_template('book_detail.html', book=book)
    except Exception as e:
        print(f"Error in book_detail route: {e}")
        abort(500)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы успешно вышли из системы', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)

