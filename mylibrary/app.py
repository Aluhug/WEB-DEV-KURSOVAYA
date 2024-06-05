from flask import Flask, render_template, url_for, flash, redirect, request, abort
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, current_user, logout_user, login_required
from forms import RegistrationForm, LoginForm, UpdateAccountForm, BookForm, ReservationForm, FeedbackForm
from models import User, Book, Reservation
from config import Config
import os
from PIL import Image

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def save_picture(form_picture):
    random_hex = os.urandom(8).hex()
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/uploads', picture_fn)
    
    output_size = (300, 300)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)

    return picture_fn

@app.route("/")
@app.route("/books")
def books():
    books = Book.query.all()
    return render_template('book_list.html', books=books)

@app.route("/register", methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route("/login", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('books'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('books'))

@app.route("/account", methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            current_user.image_file = picture_file
        current_user.username = form.username.data
        current_user.email = form.email.data
        db.session.commit()
        flash('Your account has been updated!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
    image_file = url_for('static', filename='profile_pics/' + current_user.image_file)
    return render_template('user_profile.html', title='Account', image_file=image_file, form=form)

@app.route("/user/<int:user_id>")
@login_required
def user(user_id):
    user = User.query.get_or_404(user_id)
    return render_template('user.html', title=user.username, user=user)

@app.route("/book/new", methods=['GET', 'POST'])
@login_required
def new_book():
    form = BookForm()
    if form.validate_on_submit():
        picture_file = save_picture(form.picture.data) if form.picture.data else 'default.jpg'
        book = Book(title=form.title.data, author=form.author.data, genre=form.genre.data,
                    short_description=form.short_description.data, long_description=form.long_description.data,
                    image_file=picture_file, user_id=current_user.id)
        db.session.add(book)
        db.session.commit()
        flash('Your book has been created!', 'success')
        return redirect(url_for('books'))
    return render_template('add_book.html', title='New Book', form=form)

@app.route("/book/<int:book_id>")
def book(book_id):
    book = Book.query.get_or_404(book_id)
    return render_template('book_detail.html', title=book.title, book=book)

@app.route("/book/<int:book_id>/update", methods=['GET', 'POST'])
@login_required
def update_book(book_id):
    book = Book.query.get_or_404(book_id)
    if book.author != current_user:
        abort(403)
    form = BookForm()
    if form.validate_on_submit():
        if form.picture.data:
            picture_file = save_picture(form.picture.data)
            book.image_file = picture_file
        book.title = form.title.data
        book.author = form.author.data
        book.genre = form.genre.data
        book.short_description = form.short_description.data
        book.long_description = form.long_description.data
        db.session.commit()
        flash('Your book has been updated!', 'success')
        return redirect(url_for('book', book_id=book.id))
    elif request.method == 'GET':
        form.title.data = book.title
        form.author.data = book.author
        form.genre.data = book.genre
        form.short_description.data = book.short_description
        form.long_description.data = book.long_description
    return render_template('add_book.html', title='Update Book', form=form)

@app.route("/book/<int:book_id>/delete", methods=['POST'])
@login_required
def delete_book(book_id):
    book = Book.query.get_or_404(book_id)
    if book.author != current_user:
        abort(403)
    db.session.delete(book)
    db.session.commit()
    flash('Your book has been deleted!', 'success')
    return redirect(url_for('books'))

@app.route("/reserve/<int:book_id>", methods=['GET', 'POST'])
@login_required
def reserve_book(book_id):
    form = ReservationForm()
    book = Book.query.get_or_404(book_id)
    if form.validate_on_submit():
        reservation = Reservation(book_id=book.id, user_id=current_user.id, duration=int(form.duration.data))
        db.session.add(reservation)
        db.session.commit()
        flash('The book has been reserved!', 'success')
        return redirect(url_for('books'))
    return render_template('reserve_book.html', title='Reserve Book', form=form, book=book)

@app.route("/search", methods=['GET'])
def search():
    query = request.args.get('query')
    books = Book.query.filter(Book.title.contains(query) | Book.genre.contains(query)).all()
    return render_template('book_list.html', books=books)

@app.route("/feedback", methods=['GET', 'POST'])
@login_required
def feedback():
    form = FeedbackForm()
    if form.validate_on_submit():
        # Process feedback here
        flash('Your feedback has been submitted!', 'success')
        return redirect(url_for('books'))
    return render_template('feedback.html', title='Feedback', form=form)

if __name__ == '__main__':
    app.run(debug=True)
