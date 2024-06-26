import os, datetime, re
from functools import wraps
import mysql.connector as connector
from flask import Flask, render_template, session, request, redirect, url_for, flash, abort, send_file, send_from_directory, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from werkzeug.utils import secure_filename
from mysqldb import DBConnector
from jinja2 import Environment

app = Flask(__name__)
application = app
app.config.from_pyfile('config.py')
app.config['UPLOAD_FOLDER'] = app.config.get('UPLOAD_FOLDER', 'static/uploads')
app.config['DEFAULT_COVER_IMAGE'] = app.config.get('DEFAULT_COVER_IMAGE', 'static/images/default_cover.jpg')
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg'}
ALLOWED_BOOK_EXTENSIONS = {'pdf'}
app.jinja_env.globals.update(str=str)
db_connector = DBConnector(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth'
login_manager.login_message_category = 'warning'

def allowed_file(filename, allowed_extensions):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions

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
            print(f"Error in {func.__name__}: {e}") 
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
            flash('У вас недостаточно прав для этого', 'danger')
            return redirect(request.referrer or url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

#Добавить книгу
@app.route('/admin/add_book', methods=['GET', 'POST'])
@login_required
@admin_required
@db_operation
def add_book(cursor):
    try:
        #Форма для заполнения
        if request.method == 'POST':
            title = request.form['title']
            author_first_name = request.form['author_first_name']
            author_last_name = request.form['author_last_name']
            author_middle_name = request.form.get('author_middle_name', None)
            genre = request.form['genre']
            rating = request.form['rating']
            description = request.form['description']
            cover_image = request.files['cover_image']
            book_file = request.files['book_file']

            allowed_image_extensions = {'png', 'jpg', 'jpeg'}
            allowed_book_extensions = {'pdf'}
            # Сохранение файлов обложки и книги
            if cover_image and allowed_file(cover_image.filename, allowed_image_extensions):
                cover_image_filename = secure_filename(cover_image.filename)
                cover_image.save(os.path.join(app.config['UPLOAD_FOLDER'], cover_image_filename))

            if book_file and allowed_file(book_file.filename, allowed_book_extensions):
                book_file_filename = secure_filename(book_file.filename)
                book_file.save(os.path.join(app.config['UPLOAD_FOLDER'], book_file_filename))
            else:
                book_file_filename = None
            # Вставка автора, если он не существует
            cursor.execute("""
                INSERT INTO authors (first_name, last_name, middle_name)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE first_name=VALUES(first_name), last_name=VALUES(last_name), middle_name=VALUES(middle_name)
            """, (author_first_name, author_last_name, author_middle_name))
            cursor.execute("SELECT id FROM authors WHERE first_name = %s AND last_name = %s AND middle_name = %s",
                           (author_first_name, author_last_name, author_middle_name))
            author_id = cursor.fetchone()[0]  # Используем индекс
            # Вставка жанра, если он не существует
            cursor.execute("""
                INSERT INTO genres (name)
                VALUES (%s)
                ON DUPLICATE KEY UPDATE name=VALUES(name)
            """, (genre,))
            cursor.execute("SELECT id FROM genres WHERE name = %s", (genre,))
            genre_id = cursor.fetchone()[0]  # Используем индекс

            # Вставка книги
            cursor.execute("""
                INSERT INTO books (title, author_id, genre_id, description, cover_image, book_file, rating)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (title, author_id, genre_id, description, cover_image_filename, book_file_filename, rating))

            flash('Книга успешно добавлена!', 'success')
            return redirect(url_for('books'))

        return render_template('add_book.html')
    except Exception as e:
        print(f"Error in add_book: {e}")
        flash('Произошла ошибка при добавлении книги.', 'danger')
        return render_template('add_book.html'), 500

#Пользователи
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

#Редактировать пользователя
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

#Начальная страница
@app.route('/')
def index():
    return render_template('index.html')

#Удаление пользователя
@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
@db_operation
def delete_user(cursor, user_id):
    if current_user.role_id == 2:  # Проверяем, что пользователь - администратор (библиотекарь)
        connection = db_connector.connect()
        try:
            with connection.cursor(named_tuple=True) as cursor:
                cursor.execute("DELETE FROM reviews WHERE user_id = %s", (user_id,))
                cursor.execute("DELETE FROM wishes WHERE user_id = %s", (user_id,))
                cursor.execute("DELETE FROM reservations WHERE user_id = %s", (user_id,))
                cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
                connection.commit()
            flash('Пользователь успешно удален!', 'success')
        except Exception as e:
            connection.rollback()
            flash(f'Ошибка при удалении пользователя: {str(e)}', 'danger')
    return redirect(url_for('users'))

#Аутентификация
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

#Регистрация
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

#Профиль
@app.route('/profile', methods=['GET', 'POST'])
@login_required
@db_operation
def profile(cursor):
    if request.method == 'POST':
        if current_user.role_id != 2:
            wish_text = request.form['wish_text']
            cursor.execute("""
                INSERT INTO wishes (user_id, wish_text) 
                VALUES (%s, %s)
            """, (current_user.id, wish_text))
            flash('Ваше пожелание отправлено!', 'success')
            return redirect(url_for('profile'))
    cursor.execute("SELECT id, username, email FROM users WHERE id = %s", (current_user.id,))
    user = cursor.fetchone()
    
    cursor.execute("""
        SELECT books.id AS book_id, books.title, authors.first_name AS author_first_name, authors.last_name AS author_last_name, reservations.start_date, reservations.end_date
        FROM reservations
        JOIN books ON reservations.book_id = books.id
        JOIN authors ON books.author_id = authors.id
        WHERE reservations.user_id = %s AND reservations.status = FALSE
    """, (current_user.id,))
    reserved_books = cursor.fetchall()

    cursor.execute("""
        SELECT books.id AS book_id, books.title, authors.first_name AS author_first_name, authors.last_name AS author_last_name
        FROM reservations
        JOIN books ON reservations.book_id = books.id
        JOIN authors ON books.author_id = authors.id
        WHERE reservations.user_id = %s AND reservations.status = TRUE
    """, (current_user.id,))
    reading_books = cursor.fetchall()

    return render_template('profile.html', user=user, reserved_books=reserved_books, reading_books=reading_books)

#Редактирование профиля
@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
@db_operation
def edit_profile(cursor):
    try:
        user_id = current_user.id
        if request.method == 'POST':
            username = request.form['username']
            email = request.form['email']
            cursor.execute("""
                UPDATE users SET username = %s, email = %s WHERE id = %s
            """, (username, email, user_id))
            flash('Профиль обновлен!', 'success')
            return redirect(url_for('profile'))

        cursor.execute("""
            SELECT username, email FROM users WHERE id = %s
        """, (user_id,))
        user = cursor.fetchone()

        return render_template('edit_profile.html', user=user)
    except Exception as e:
        print(f"Error in edit_profile route: {e}")
        abort(500)


#Книги 
@app.route('/books', methods=['GET', 'POST'])
@login_required
@db_operation
def books(cursor):
    title = request.form.get('title') if request.method == 'POST' else request.args.get('title')
    author = request.form.get('author') if request.method == 'POST' else request.args.get('author')
    genre = request.form.get('genre') if request.method == 'POST' else request.args.get('genre')

    query = """
        SELECT books.id, books.title, CONCAT(authors.first_name, ' ', authors.last_name) AS author, genres.name AS genre, books.description, books.cover_image
        FROM books
        JOIN authors ON books.author_id = authors.id
        JOIN genres ON books.genre_id = genres.id
        WHERE 1=1
    """
    params = []

    if title:
        query += " AND books.title LIKE %s"
        params.append(f"%{title}%")

    if author:
        query += " AND CONCAT(authors.first_name, ' ', authors.last_name) = %s"
        params.append(author)

    if genre:
        query += " AND genres.name = %s"
        params.append(genre)

    cursor.execute(query, params)
    books = cursor.fetchall()

    cursor.execute("SELECT DISTINCT CONCAT(authors.first_name, ' ', authors.last_name) AS author FROM authors")
    authors = cursor.fetchall()

    cursor.execute("SELECT DISTINCT name AS genre FROM genres")
    genres = cursor.fetchall()

    return render_template('books.html', books=books, authors=authors, genres=genres, title=title, author=author, genre=genre)

#Подробная информация о книге
@app.route('/book/<int:book_id>', methods=['GET', 'POST'])
@login_required
@db_operation
def book_detail(cursor, book_id):
    try:
        if request.method == 'POST':
            if 'mark_reading' in request.form:
                cursor.execute("""
                    INSERT INTO reservations (user_id, book_id, start_date, end_date, status) 
                    VALUES (%s, %s, %s, %s, TRUE)
                    ON DUPLICATE KEY UPDATE status = VALUES(status)
                """, (current_user.id, book_id, datetime.date.today(), datetime.date.today() + datetime.timedelta(days=180)))
                flash('Книга добавлена в список читаемых!', 'success')
            elif 'unmark_reading' in request.form:
                cursor.execute("""
                    DELETE FROM reservations 
                    WHERE user_id = %s AND book_id = %s AND status = TRUE
                """, (current_user.id, book_id))
                flash('Книга убрана из списка читаемых!', 'success')
            elif 'reserve_book' in request.form:
                cursor.execute("""
                    INSERT INTO reservations (user_id, book_id, start_date, end_date, status) 
                    VALUES (%s, %s, %s, %s, FALSE)
                """, (current_user.id, book_id, datetime.date.today(), datetime.date.today() + datetime.timedelta(days=180)))
                flash('Книга забронирована!', 'success')
            elif 'unreserve_book' in request.form:
                cursor.execute("""
                    DELETE FROM reservations 
                    WHERE user_id = %s AND book_id = %s AND status = FALSE
                """, (current_user.id, book_id))
                flash('Бронирование книги отменено!', 'success')
            elif 'review_text' in request.form and 'rating' in request.form:
                review_text = request.form['review_text']
                rating = request.form['rating']
                cursor.execute("""
                    INSERT INTO reviews (user_id, book_id, review_text, rating) 
                    VALUES (%s, %s, %s, %s)
                """, (current_user.id, book_id, review_text, rating))
                flash('Ваш отзыв добавлен!', 'success')
            return redirect(url_for('book_detail', book_id=book_id))

        cursor.execute("""
            SELECT books.id, books.title, CONCAT(authors.first_name, ' ', authors.last_name) AS author, genres.name AS genre, books.description, 
                   COALESCE(books.cover_image, %s) AS cover_image,
                   books.book_file, AVG(reviews.rating) AS average_rating, books.rating AS book_rating
            FROM books
            JOIN authors ON books.author_id = authors.id
            JOIN genres ON books.genre_id = genres.id
            LEFT JOIN reviews ON books.id = reviews.book_id
            WHERE books.id = %s
            GROUP BY books.id, authors.first_name, authors.last_name, genres.name, books.description, books.cover_image, books.book_file, books.rating
        """, (app.config['DEFAULT_COVER_IMAGE'], book_id))
        book = cursor.fetchone()
        if book is None:
            abort(404)

        cursor.execute("""
            SELECT users.username, reviews.review_text, reviews.rating
            FROM reviews
            JOIN users ON reviews.user_id = users.id
            WHERE reviews.book_id = %s
        """, (book_id,))
        reviews = cursor.fetchall()

        cursor.execute("""
            SELECT 1 AS is_reading FROM reservations
            WHERE user_id = %s AND book_id = %s AND status = TRUE
        """, (current_user.id, book_id))
        is_reading = cursor.fetchone() is not None

        cursor.execute("""
            SELECT 1 AS is_reserved FROM reservations
            WHERE user_id = %s AND book_id = %s AND status = FALSE
        """, (current_user.id, book_id))
        is_reserved = cursor.fetchone() is not None

        return render_template('book_detail.html', book=book, reviews=reviews, is_reading=is_reading, is_reserved=is_reserved)
    except Exception as e:
        print(f"Error in book_detail route: {e}")
        abort(500)

#Читать книгу
@app.route('/read_book/<int:book_id>')
@login_required
@db_operation
def read_book(cursor, book_id):
    try:
        cursor.execute("""
            SELECT book_file
            FROM books
            WHERE id = %s
        """, (book_id,))
        book = cursor.fetchone()
        if book is None:
            abort(404)

        book_file = book[0]
        book_file_path = os.path.join(app.config['UPLOAD_FOLDER'], book_file)
        if not os.path.exists(book_file_path):
            abort(404)

        return render_template('read_book.html', book_file=book_file)
    except Exception as e:
        print(f"Error in read_book route: {e}")
        abort(500)

#Редактировать книгу
@app.route('/admin/edit_book/<int:book_id>', methods=['GET', 'POST'])
@login_required
@admin_required
@db_operation
def edit_book(cursor, book_id):
    try:
        if request.method == 'POST':
            title = request.form['title']
            author_first_name = request.form['author_first_name']
            author_last_name = request.form['author_last_name']
            author_middle_name = request.form.get('author_middle_name', None)
            genre = request.form['genre']
            description = request.form['description']
            cover_image = request.files['cover_image']
            book_file = request.files['book_file']

            if cover_image and allowed_file(cover_image.filename, ALLOWED_IMAGE_EXTENSIONS):
                cover_image_filename = secure_filename(cover_image.filename)
                cover_image.save(os.path.join(app.config['UPLOAD_FOLDER'], cover_image_filename))
            else:
                cover_image_filename = None

            if book_file and allowed_file(book_file.filename, ALLOWED_BOOK_EXTENSIONS):
                book_file_filename = secure_filename(book_file.filename)
                book_file.save(os.path.join(app.config['UPLOAD_FOLDER'], book_file_filename))
            else:
                book_file_filename = None

            # Обновление автора
            cursor.execute("""
                INSERT INTO authors (first_name, last_name, middle_name)
                VALUES (%s, %s, %s)
                ON DUPLICATE KEY UPDATE first_name=VALUES(first_name), last_name=VALUES(last_name), middle_name=VALUES(middle_name)
            """, (author_first_name, author_last_name, author_middle_name))
            cursor.execute("SELECT id FROM authors WHERE first_name = %s AND last_name = %s AND middle_name = %s",
                           (author_first_name, author_last_name, author_middle_name))
            author_id = cursor.fetchone().id

            # Обновление жанра
            cursor.execute("""
                INSERT INTO genres (name)
                VALUES (%s)
                ON DUPLICATE KEY UPDATE name=VALUES(name)
            """, (genre,))
            cursor.execute("SELECT id FROM genres WHERE name = %s", (genre,))
            genre_id = cursor.fetchone().id

            # Обновление книги
            if cover_image_filename and book_file_filename:
                cursor.execute("""
                    UPDATE books
                    SET title = %s, author_id = %s, genre_id = %s, description = %s, cover_image = %s, book_file = %s
                    WHERE id = %s
                """, (title, author_id, genre_id, description, cover_image_filename, book_file_filename, book_id))
            elif cover_image_filename:
                cursor.execute("""
                    UPDATE books
                    SET title = %s, author_id = %s, genre_id = %s, description = %s, cover_image = %s
                    WHERE id = %s
                """, (title, author_id, genre_id, description, cover_image_filename, book_id))
            elif book_file_filename:
                cursor.execute("""
                    UPDATE books
                    SET title = %s, author_id = %s, genre_id = %s, description = %s, book_file = %s
                    WHERE id = %s
                """, (title, author_id, genre_id, description, book_file_filename, book_id))
            else:
                cursor.execute("""
                    UPDATE books
                    SET title = %s, author_id = %s, genre_id = %s, description = %s
                    WHERE id = %s
                """, (title, author_id, genre_id, description, book_id))

            flash('Книга успешно обновлена!', 'success')
            return redirect(url_for('book_detail', book_id=book_id))

        cursor.execute("""
            SELECT books.id, books.title, authors.first_name AS author_first_name, authors.last_name AS author_last_name, 
                   authors.middle_name AS author_middle_name, genres.name AS genre, books.description, 
                   COALESCE(books.cover_image, %s) AS cover_image, books.book_file
            FROM books
            JOIN authors ON books.author_id = authors.id
            JOIN genres ON books.genre_id = genres.id
            WHERE books.id = %s
        """, (app.config['DEFAULT_COVER_IMAGE'], book_id))
        book = cursor.fetchone()
        if book is None:
            abort(404)

        return render_template('edit_book.html', book=book)
    except Exception as e:
        print(f"Error in edit_book route: {e}")
        abort(500)

#Скачать книгу
@app.route('/download_book/<int:book_id>')
@login_required
@db_operation
def download_book(cursor, book_id):
    try:
        cursor.execute("SELECT book_file FROM books WHERE id = %s", (book_id,))
        book = cursor.fetchone()
        if book is None or book[0] is None:
            abort(404)
        return send_from_directory(app.config['UPLOAD_FOLDER'], book[0].split('/')[-1], as_attachment=True)
    except Exception as e:
        print(f"Error in download_book: {e}")
        abort(500)

#Удаление книги
@app.route('/admin/delete_book/<int:book_id>', methods=['POST'])
@login_required
@admin_required
@db_operation
def delete_book(cursor, book_id):
    if current_user.role_id == 2:  # Проверяем, что пользователь - администратор (библиотекарь)
        try:
            cursor.execute("DELETE FROM reviews WHERE book_id = %s", (book_id,))
            cursor.execute("DELETE FROM reservations WHERE book_id = %s", (book_id,))
            cursor.execute("DELETE FROM books WHERE id = %s", (book_id,))
            cursor.connection.commit()  # Используем явное соединение для commit
            flash('Книга успешно удалена!', 'success')
        except Exception as e:
            flash(f'Ошибка при удалении книги: {str(e)}', 'danger')
    else:
        flash('У вас нет прав для выполнения этого действия.', 'danger')
    return redirect(url_for('books'))

#Пожелания
@app.route('/wishes', methods=['GET', 'POST'])
@admin_required
@login_required
@db_operation
def wishes(cursor):
    try:
        if request.method == 'POST' and current_user.role_id != 2:  # Только обычные пользователи могут оставлять пожелания
            wish_text = request.form['wish_text']
            cursor.execute("""
                INSERT INTO wishes (user_id, wish_text) VALUES (%s, %s)
            """, (current_user.id, wish_text))
            flash('Ваше пожелание отправлено!', 'success')
            return redirect(url_for('wishes'))

        if current_user.role_id == 2:  # Библиотекари могут просматривать пожелания
            cursor.execute("""
                SELECT wishes.id, users.username, wishes.wish_text, wishes.created_at
                FROM wishes
                JOIN users ON wishes.user_id = users.id
                ORDER BY wishes.created_at DESC
            """)
            all_wishes = cursor.fetchall()
            return render_template('view_wishes.html', wishes=all_wishes)
        
        return render_template('wishes.html')
    except Exception as e:
        print(f"Error in wishes route: {e}")
        abort(500)

#Выход из системы
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы успешно вышли из системы', 'success')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)