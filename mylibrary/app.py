from flask import Flask, render_template

app = Flask(__name__)
app.config.from_pyfile('config.py')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/auth')
def auth():
    return render_template('auth.html')

@app.route('/register')
def register():
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
