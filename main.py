import os
import smtplib
from random import randint

from flask import Flask, render_template, redirect, url_for, request
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Update
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("FLASK_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get("DB_URI", "sqlite:///ejtodo.db")

db = SQLAlchemy()
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)

app.app_context().push()


class Users(UserMixin, db.Model):
    __tablename__ = "userss"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))

    work_board = relationship("Board", back_populates="author")
    todos = relationship("Todo", back_populates="todo_author")
    doings = relationship("Doing", back_populates="doing_author")
    dons = relationship("Done", back_populates="done_author")


class Board(db.Model):
    __tablename__ = "boards"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey("userss.id"))
    author = relationship("Users", back_populates="work_board")
    todos = relationship("Todo", back_populates="parent_board_todo")
    doings = relationship("Doing", back_populates="parent_board_doing")
    dons = relationship("Done", back_populates="parent_board_done")


class Todo(db.Model):
    __tablename__ = "todo"
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)

    author_id = db.Column(db.Integer, db.ForeignKey("userss.id"))
    board_id = db.Column(db.Integer, db.ForeignKey("boards.id"))
    todo_author = relationship("Users", back_populates="todos")
    parent_board_todo = relationship("Board", back_populates="todos")


class Doing(db.Model):
    __tablename__ = "doing"
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)

    author_id = db.Column(db.Integer, db.ForeignKey("userss.id"))
    board_id = db.Column(db.Integer, db.ForeignKey("boards.id"))
    doing_author = relationship("Users", back_populates="doings")
    parent_board_doing = relationship("Board", back_populates="doings")


class Done(db.Model):
    __tablename__ = "done"
    id = db.Column(db.Integer, primary_key=True)
    data = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)

    author_id = db.Column(db.Integer, db.ForeignKey("userss.id"))
    board_id = db.Column(db.Integer, db.ForeignKey("boards.id"))
    done_author = relationship("Users", back_populates="dons")
    parent_board_done = relationship("Board", back_populates="dons")


db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return db.get_or_404(Users, user_id)


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]
        result = db.session.execute(db.select(Users).where(Users.email == email)).scalar()
        if result is None:
            num_list = []
            for i in range(0, 6):
                num = randint(0, 9)
                num_list.append(num)
            str_list = [str(i) for i in num_list]
            rand = ""
            code = rand.join(str_list)
            # print(code)
            send_verification(name, code, email)
            return redirect(url_for("register_verify", name=name, email=email, password=password, code=code))
        else:
            error = "Already registered!! Please login"
            return render_template("register.html", error=error)

    return render_template("register.html")


def send_verification(name, codes, email):
    username = os.environ.get('email')
    passwords = os.environ.get('password')
    email_message = f"Subject:Verify your Email\n\nHi {name},\nPlease enter this code in EJ Todo Board \nCode:{codes}"
    # print(email_message)
    with smtplib.SMTP("smtp.gmail.com", port=587) as connection:
        connection.starttls()
        connection.login(user=username, password=passwords)
        connection.sendmail(from_addr=username, to_addrs=email,
                            msg=email_message.encode('utf-8'))
        # print("Mail sent")


@app.route('/register_verify', methods=["GET", "POST"])
def register_verify():
    name = request.args.get("name")
    email = request.args.get("email")
    password = request.args.get("password")
    code = request.args.get("code")

    if request.method == "POST":
        code_returned = request.form["code"]
        # print(code_returned)
        if code_returned == code:
            hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
            user = Users(name=name, email=email, password=hashed_password)
            db.session.add(user)
            db.session.commit()
            return render_template("login.html", success="Registered Successfully please login!!")
        else:
            error = "Verification code is wrong"
            return render_template("verify.html", error=error, name=name, email=email, password=password, code=code)

    return render_template("verify.html", name=name, email=email, password=password, code=code)


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        result = db.session.execute(db.select(Users).where(Users.email == email)).scalar()

        if result is None:
            error = "Email id is incorrect or not registered"
            return render_template("login.html", error1=error, email=email, password=password)
        else:
            check_password_is_true = check_password_hash(result.password, password)
            if check_password_is_true is True:
                login_user(result)
                return redirect(url_for('welcome', user_id=current_user.id))
            else:
                error = "Password is Incorrect"
                return render_template("login.html", error2=error, email=email, password=password)
    return render_template("login.html")


@app.route('/logout')
@login_required
def logout():
    logout_user()
    logouts = "Logout Successful"
    return render_template("index.html", logout=logouts)


@app.route('/forgot_password', methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]
        # print(email)

        result = db.session.execute(db.select(Users).where(Users.email == email)).scalar()
        # print(result)
        if result is None:
            error = "Email is not registered, Please register first!!"
            return render_template("forgot.html", error=error)
        else:
            num_lists = []
            for ii in range(0, 6):
                nums = randint(0, 9)
                num_lists.append(nums)
            str_lists = [str(ii) for ii in num_lists]
            rands = ""
            codess = rands.join(str_lists)
            # print(codess)
            send_verification(name="", email=email, codes=codess)
            return redirect(url_for("verify", email_code=codess, email=email))

    return render_template("forgot.html")


@app.route('/verify', methods=["GET", "POST"])
def verify():
    email_code = request.args.get("email_code")
    # print(email_code)
    email = request.args.get("email")
    # print(email)
    error = ""
    success = ""
    update = False
    if request.method == "POST":
        code_forgot_password = request.form["code"]
        # print(code_forgot_password)
        if code_forgot_password == email_code:
            update = True
            success = "Verification successfully,\n Enter your new password now!!"
            redirect(url_for("verify", success=success, update=update, error="", email=email))
        else:
            error = "Verification code is wrong"
            redirect(url_for("verify", error=error, email_code=email_code, success="", email=email))

    return render_template("update_password.html", error=error, success=success, email_code=email_code, update=update,
                           email=email)


@app.route('/update_passwords', methods=["GET", "POST"])
def update_passwords():
    password = request.form["password"]
    # print(password)
    email = request.args.get("email")
    # print(email)
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256', salt_length=8)
    db.session.execute(Update(Users).where(Users.email == email).values(password=hashed_password))
    db.session.commit()
    success = "Password changed Successfully"
    return render_template("login.html", success=success)


@app.route('/', methods=["GET", "POST"])
def welcome():
    create_board = False
    logout = "Welcome to EJ Blog, PLease Register or Login"
    result = db.session.execute(db.select(Board))
    results = result.scalars()
    user_result = db.session.execute(db.select(Users)).scalars()

    if request.method == "POST":
        create_board = request.args.get("create_board")
        return render_template("index.html", user_id=current_user.id, user=True,
                               login=db.get_or_404(Users, current_user.id), create_board=create_board,
                               board_lists_data=results)
    if current_user in user_result:
        return render_template("index.html", user_id=current_user.id, user=True,
                               login=db.get_or_404(Users, current_user.id), create_board=create_board,
                               board_lists_data=results)
    else:
        return render_template("index.html", user=False, logout=logout)


@app.route('/cancel_board', methods=["POST"])
@login_required
def cancel_board():
    if request.method == "POST":
        create_board = request.args.get("create_board")
        return redirect(url_for("welcome",create_board=create_board))


@app.route('/add_board', methods=["POST"])
@login_required
def add_board():
    user = db.session.execute(db.select(Users).where(Users.id == current_user.id)).scalar()
    if request.method == "POST":
        title = request.form.get("title")
        add_new_board = Board(title=title, author=user)
        db.session.add(add_new_board)
        db.session.commit()
        return redirect(url_for("welcome"))


@app.route('/delete_board', methods=["POST"])
@login_required
def delete_board():
    if request.method == "POST":
        board_id = request.args.get("board_id")
        board_to_delete = db.session.execute(db.select(Board).where(Board.id == board_id)).scalar()
        db.session.delete(board_to_delete)
        db.session.commit()
        return redirect(url_for('welcome'))


@app.route('/show_task_board', methods=["GET", "POST"])
@login_required
def show_task_board():
    task_submit_show1 = request.args.get("task_submit_show1")
    task_submit_show2 = request.args.get("task_submit_show2")
    task_submit_show3 = request.args.get("task_submit_show3")

    if task_submit_show1 is None:
        task_submit_show1 = False
    if task_submit_show2 is None:
        task_submit_show2 = False
    if task_submit_show3 is None:
        task_submit_show3 = False

    board_id = request.args.get("board_id")
    # print(board_id)
    # print(type(board_id))
    create_board = False

    todo = db.session.execute(db.select(Todo))
    results_todo = todo.scalars()

    doing = db.session.execute(db.select(Doing))
    results_doing = doing.scalars()

    done = db.session.execute(db.select(Done))
    results_done = done.scalars()

    # user_result = db.session.execute(db.select(Users)).scalars()

    if request.method == "POST":
        task_submit_show1 = request.args.get("task_submit_show1")
        task_submit_show2 = request.args.get("task_submit_show2")
        task_submit_show3 = request.args.get("task_submit_show3")
        board_id = request.args.get("board_id")
        # print(board_id)
        # print(board_id)
        # print(type(board_id))
        todo = db.session.execute(db.select(Todo))
        results_todo = todo.scalars()

        doing = db.session.execute(db.select(Doing))
        results_doing = doing.scalars()

        done = db.session.execute(db.select(Done))
        results_done = done.scalars()

        return render_template("show_task_board.html", user_id=current_user.id, user=True,
                               login=db.get_or_404(Users, current_user.id), create_board=create_board, todo=results_todo,
                               doing=results_doing, done=results_done, board_id=board_id
                               , task_submit_show1=task_submit_show1, task_submit_show2=task_submit_show2,
                               task_submit_show3=task_submit_show3)
    return render_template("show_task_board.html", user_id=current_user.id, user=True,
                           login=db.get_or_404(Users, current_user.id), create_board=create_board, todo=results_todo,
                           doing=results_doing, done=results_done, board_id=board_id
                           , task_submit_show1=task_submit_show1, task_submit_show2=task_submit_show2,
                           task_submit_show3=task_submit_show3)


@app.route('/show_task_board_close', methods=["POST"])
@login_required
def show_task_board_close():
    if request.method == "POST":
        board_id = request.args.get("board_id")
        task_submit_show1 = request.args.get("task_submit_show1")
        task_submit_show2 = request.args.get("task_submit_show2")
        task_submit_show3 = request.args.get("task_submit_show3")
        return redirect(
            url_for("show_task_board", ask_submit_show1=task_submit_show1, task_submit_show2=task_submit_show2,
                    task_submit_show3=task_submit_show3, board_id=board_id))


@app.route('/add_task', methods=["POST"])
@login_required
def add_task():
    board_id = request.args.get("board_id")
    # print(board_id)
    user = db.session.execute(db.select(Users).where(Users.id == current_user.id)).scalar()
    board = db.session.execute(db.select(Board).where(Board.id == board_id)).scalar()
    # print(user)
    if request.method == "POST":
        tast_type = request.args.get("type")
        # print(tast_type)
        if tast_type == "todo":
            data = request.form.get("data")
            date = request.form.get("date")
            add_new_task = Todo(data=data, date=date, todo_author=user, parent_board_todo=board)
            db.session.add(add_new_task)
            db.session.commit()
        elif tast_type == "doing":
            data = request.form.get("data")
            date = request.form.get("date")
            add_new_task = Doing(data=data, date=date, doing_author=user, parent_board_doing=board)
            db.session.add(add_new_task)
            db.session.commit()
        else:
            data = request.form.get("data")
            date = request.form.get("date")
            add_new_task = Done(data=data, date=date, done_author=user, parent_board_done=board)
            db.session.add(add_new_task)
            db.session.commit()
        return redirect(url_for('show_task_board', board_id=board_id))


@app.route('/delete_task', methods=["POST"])
@login_required
def delete_task():
    if request.method == "POST":
        board_id = request.args.get("board_id")
        tast_type = request.args.get("type")
        if tast_type == "todo":
            id = request.args.get("id")
            todo_to_delete = db.session.execute(db.select(Todo).where(Todo.id == id)).scalar()
            db.session.delete(todo_to_delete)
            db.session.commit()
        elif tast_type == "doing":
            id = request.args.get("id")
            doing_to_delete = db.session.execute(db.select(Doing).where(Doing.id == id)).scalar()
            db.session.delete(doing_to_delete)
            db.session.commit()
        else:
            id = request.args.get("id")
            done_to_delete = db.session.execute(db.select(Done).where(Done.id == id)).scalar()
            db.session.delete(done_to_delete)
            db.session.commit()
        return redirect(url_for('show_task_board', board_id=board_id))


@app.route('/done', methods=["POST"])
@login_required
def done():
    if request.method == "POST":
        board_id = request.args.get("board_id")
        tast_type = request.args.get("type")
        user = db.session.execute(db.select(Users).where(Users.id == current_user.id)).scalar()
        board = db.session.execute(db.select(Board).where(Board.id == board_id)).scalar()
        if tast_type == "todo":
            id = request.args.get("id")
            # print(id)
            todo_doing = db.session.execute(db.select(Todo).where(Todo.id == id)).scalar()
            data = todo_doing.data
            date = todo_doing.date
            todo_doing_add = Doing(data=data, date=date, doing_author=user, parent_board_doing=board)
            db.session.add(todo_doing_add)
            db.session.delete(todo_doing)
            db.session.commit()
        else:
            id = request.args.get("id")
            doing_done = db.session.execute(db.select(Doing).where(Doing.id == id)).scalar()
            data = doing_done.data
            date = doing_done.date
            doing_done_add = Done(data=data, date=date, done_author=user, parent_board_done=board)
            db.session.add(doing_done_add)
            db.session.delete(doing_done)
            db.session.commit()
        return redirect(url_for("show_task_board", board_id=board_id))


if __name__ == "__main__":
    app.run(debug=False)
