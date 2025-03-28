import os
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
import secrets

# Инициализация Flask приложения
app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Получение абсолютного пути к корню проекта
basedir = os.path.abspath(os.path.dirname(__file__))

# Настройка почты
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'tynybekovjanyshbek@gmail.com'  # Замените на ваш email
app.config['MAIL_PASSWORD'] = 'icbvlisqskeunccq'  # Замените на ваш пароль приложения
app.config['MAIL_DEFAULT_SENDER'] = 'tynybekovjanyshbek@gmail.com'

# Настройка SQLAlchemy
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'supersecretkey'

# Инициализация расширений
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
mail = Mail(app)

# Модель пользователя
class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    reset_token = db.Column(db.String(32), nullable=True)

# Главная страница перенаправляет на вход
@app.route('/')
def home():
    return redirect(url_for('signin'))

# Страница входа
@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = Users.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Вход выполнен успешно!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Неверный email или пароль!', 'danger')

    return render_template('signin.html')

# Страница регистрации
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Пароли не совпадают!', 'danger')
            return redirect(url_for('signup'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = Users(email=email, username=username, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Аккаунт успешно создан!', 'success')
            return redirect(url_for('signin'))
        except:
            db.session.rollback()
            flash('Ошибка: Email или имя пользователя уже существуют!', 'danger')

    return render_template('signup.html')

# Страница запроса восстановления пароля
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = Users.query.filter_by(email=email).first()

        if user:
            # Генерация уникального токена
            token = secrets.token_hex(16)
            user.reset_token = token
            db.session.commit()

            # Создание ссылки для сброса пароля
            reset_link = f'http://127.0.0.1:5000/reset-password?token={token}'
            msg = Message('Запрос на сброс пароля', recipients=[email])
            msg.body = f'Чтобы сбросить пароль, перейдите по следующей ссылке: {reset_link}'
            mail.send(msg)

            flash('Ссылка для сброса пароля отправлена на ваш email!', 'info')
            return redirect(url_for('signin'))
        else:
            flash('Email не найден!', 'danger')

    return render_template('forgot-password.html')

# Страница сброса пароля
@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    token = request.args.get('token')
    user = Users.query.filter_by(reset_token=token).first()

    if not user:
        flash('Неверный или просроченный токен!', 'danger')
        return redirect(url_for('signin'))

    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('Пароли не совпадают!', 'danger')
            return redirect(url_for('reset_password', token=token))

        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user.password = hashed_password
        user.reset_token = None
        db.session.commit()

        flash('Пароль успешно сброшен!', 'success')
        return redirect(url_for('signin'))

    return render_template('reset-password.html', token=token)

# Страница дашборда
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Пожалуйста, сначала войдите в систему.', 'warning')
        return redirect(url_for('signin'))
    return f"Добро пожаловать, {session['username']}!"

# Выход из системы
@app.route('/logout')
def logout():
    session.clear()
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('signin'))

# Инициализация базы данных
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)