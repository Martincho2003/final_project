import json
import hashlib
from functools import wraps
from flask import request, Flask, flash, redirect, jsonify
from flask import render_template
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import (
        TimedJSONWebSignatureSerializer as Serializer,
        BadSignature,
        SignatureExpired
    )


app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/dev.db'
app.secret_key = "wakbcawiluchawoedhaewu2342bwa"

db = SQLAlchemy(app)

def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def __init__(self, **kwargs):
        if 'password' in kwargs:
            kwargs['password'] = hash_password(kwargs['password'])
        super(User, self).__init__(**kwargs)

    def __repr__(self):
        return '<User %r>' % self.username

    def verify_password(self, password):
        return self.password == hash_password(password)

    def generate_token(self):
        s = Serializer(app.secret_key, expires_in=600)
        return s.dumps({'username': self.username})

    @staticmethod
    def find_by_token(token):
        if not token:
            return None

        try:
            s = Serializer(app.secret_key)
            payload = s.loads(token)
            return User.query.filter_by(username=payload.get('username')).first()
        except SignatureExpired:
            return None

db.create_all()
def verify_token(token):
    s = Serializer(app.secret_key)
    try:
        s.loads(token)
    except SignatureExpired:
        return False
    except BadSignature:
        return False
    return True

def require_login(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = request.cookies.get('token')
        if not token or not verify_token(token):
            flash('You have to be logged in to access this page')
            return redirect('/login')
        return func(*args, **kwargs)
    return wrapper

def stop_logged_users(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        token = request.cookies.get('token')
        if token and verify_token(token):
            flash('You\'re already logged in.')
            return redirect('/')
        return func(*args, **kwargs)
    return wrapper

@app.route("/")
def hello():
    return render_template("base.html")

@app.route('/login', methods=['GET', 'POST'])
@stop_logged_users
def login():
    if request.method == 'GET':
        return render_template('login.html')
    else:
        data = json.loads(request.data.decode('ascii'))
        username = data['username']
        password = data['password']

        user = User.query.filter_by(username=username).first()
        if not user or not user.verify_password(password):
            return jsonify({'token': None})
        token = user.generate_token()
        return jsonify({'token': token.decode('ascii')})

@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
    else:
        username = request.form['username']
        password = request.form['password']

    try:
        user = User(
                username=username,
                password=password,
                )
        db.session.add(user)
        db.session.commit()
        return redirect('/')
    except Exception as e:
        flash('Error: {}'.format(e))
        return redirect(request.url)


if __name__ == "__main__":
	app.run()