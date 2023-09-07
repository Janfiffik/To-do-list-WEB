import sqlite3

import werkzeug
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager,  current_user, logout_user
import json

app = Flask(__name__)
app.app_context().push()
app.config["SECRET_KEY"] = "hfdav4a5dfvsafdgSD4VSDVASZXCSDFBVsgsdfv"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
Bootstrap(app)
db_path = "instance/users.db"


log_man = LoginManager()
log_man.init_app(app)


@log_man.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))


class Tasks(db.Model):
    id = db.Column(db.Integer, unique=False, primary_key=True)
    user_id = db.Column(db.Integer)
    date = db.Column(db.String(100), unique=False)
    task = db.Column(db.String(100), unique=False)

db.create_all()


@app.route("/", methods=["GET", "POST"])
def home():
    return render_template("index.html", logged_in=current_user.is_authenticated)


@app.route("/register", methods=["POST", "GET"])
def register():

    if request.method == "POST":
        name = request.form.get('name')

        if User.query.filter_by(name=name).first():
            return render_template('login.html', error="Name already exist, please Log-in.")
        else:
            password = request.form.get('password')
            hash_pass = werkzeug.security.generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
            
            new_user = User(name=request.form.get('name'),
                            password=hash_pass)

            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('to_do_list'))

    return render_template("register.html", logged_in=current_user.is_authenticated)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        name = request.form.get("name")
        password = request.form.get('password')
        user = User.query.filter_by(name=name).first()

        if user is None:
            error = "User name doesn't exist."

        elif check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('to_do_list'))

        else:
            error = "Invalid password"

    return render_template('login.html', error=error, logged_in=current_user.is_authenticated)


@app.route("/to_do_list", methods=["POST", "GET"])
def to_do_list():
    user_id = current_user.id

    try:
        connection = sqlite3.connect(db_path)
        cursor = connection.cursor()
        query = f"SELECT * FROM tasks WHERE user_id={user_id}"
        cursor.execute(query)
        results = cursor.fetchall()
        connection.close()

    except:
        results = None

    if request.method == "POST":
        to_do = request.form.get("task")
        date = request.form.get("date")
        new_task = Tasks(user_id=user_id,
                         date=date,
                         task=to_do)
        db.session.add(new_task)
        db.session.commit()
        db.session.close()
        return redirect(url_for('to_do_list'))

    return render_template('to_do_list.html', tasks=results, name=current_user.name, logged_in=True)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route("/delete", methods=["GET", "POST"])
def delete():
    task_id = request.args.get("id")
    task = Tasks.query.get(task_id)
    db.session.delete(task)
    db.session.commit()
    return redirect("/to_do_list")


@app.route("/update", methods=["GET", "POST"])
def update():
    if request.method == "POST":
        new_date = request.form.get("change_date")
        print(str(new_date))
        task_id = request.form.get("id")

        connection = sqlite3.connect(db_path)
        cursor = connection.cursor()
        query_1 = f"UPDATE tasks SET date='{new_date}' WHERE id={task_id}"
        cursor.execute(query_1)
        connection.commit()
        connection.close()

    return redirect("/to_do_list")


if __name__ == "__main__":
    app.run(debug=True)
