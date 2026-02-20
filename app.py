from flask import Flask, render_template, request, url_for, redirect, flash
from config import Config
from flask_migrate import Migrate
from models import db, User, PasswordResetId 
from sqlalchemy import select
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
from flask_mail import Mail, Message

app = Flask(__name__)
app.config.from_object(Config)
db.init_app(app)

migrate = Migrate(app, db)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "You need to be authenticated to access that page"
login_manager.login_message_category = "error"

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

mail = Mail(app)


@app.route("/")
@login_required
def home():
    return render_template("home.html")

@app.route("/register", methods=["GET", "POST"])
def register():

    if current_user.is_authenticated:
        return redirect(url_for("home"))


    if request.method == "POST":

        # grab form data
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if len(password) < 5:
            flash("Password must be at least 5 characters", "error")
            return redirect(url_for("register"))
        
        if password != confirm_password:
            flash("Passwords do not match", "error")
            return redirect(url_for("register"))

        # make sure email and username are not being used
        if db.session.scalar(
            select(User).where(User.email == email)
        ):
            flash("Email already in use", "error")
            return redirect(url_for("register"))

        if db.session.scalar(
            select(User).where(User.username == username)
        ):
            flash("Username already in use", "error")
            return redirect(url_for("register"))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        user = User(
            username = username, 
            email = email, 
            password = hashed_password
        )
        db.session.add(user)
        db.session.commit()

        flash("Account created successfully", "success")
        return redirect(url_for("login"))



    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():

    if current_user.is_authenticated:
        return redirect(url_for("home"))

    if request.method == 'POST':
        username = request.form.get("username")
        password = request.form.get("password")

        user = db.session.scalar(
            select(User).where(User.username == username)
        )
        if user:
            # determine if password is correct
            if bcrypt.check_password_hash(user.password, password):
                login_user(user)

                next = request.args.get('next')
                return redirect(next or url_for('home'))
            
            flash("Invalid password entered", "error")
            return redirect(url_for("login"))
            
        flash("Invalid username entered", "error")
        return redirect(url_for("login"))


    return render_template("login.html")


@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    if current_user.is_authenticated:
        return redirect(url_for("home"))

    if request.method == 'POST':
        email = request.form.get("email")

        user = db.session.scalar(
            select(User).where(User.email == email)
        )

        if not user:
            flash("No user with that email found", "error")
            return redirect(url_for("forgot_password"))
        
        # delete other potentially existing codes
        user.password_reset_ids.clear()

        new_password_reset_id = PasswordResetId(user=user)
        db.session.add(new_password_reset_id)
        db.session.commit()

        # http://127.0.0.1:5000/reset-password/fffsdsd-3r3edsfddf-efsdddssd/
        password_reset_link = url_for("reset_password", reset_id=new_password_reset_id.reset_id , _external=True)
        
        msg = Message(
            subject = "Reset your password",
            recipients = [email],
            body = f"Reset your password using the link below\n\n{password_reset_link}"
        )
        try:
            mail.send(msg)

            context = {
                "reset_sent": True,
                "email": email
            }
            return render_template("forgot_password.html", **context) 
        except Exception as e:
            print(f"Error: {e}")


    return render_template("forgot_password.html", reset_sent=False)

@app.route("/reset-password/<reset_id>", methods=["GET", "POST"])
def reset_password(reset_id):

    if current_user.is_authenticated:
        return redirect(url_for("home"))

    reset_id_object = db.session.scalar(
        select(PasswordResetId).where(PasswordResetId.reset_id == reset_id)
    )

    if not reset_id_object:
        flash("Invalid reset link", "error")
        return redirect(url_for("forgot_password"))

    # delete reset id of it has expired
    if reset_id_object.is_expired():
        db.session.delete(reset_id)
        db.session.commit()

        flash("Expired reset link", "error")
        return redirect(url_for("forgot_password"))
    
    if request.method == "POST":

        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if len(password) < 5:
            flash("Password must be at east 5 characters long", "error")
            return redirect(url_for("reset_password", reset_id=reset_id))

        if password != confirm_password:
            flash("Passwords do not match", "error")
            return redirect(url_for("reset_password", reset_id=reset_id))
        
        user = reset_id_object.user
        user.password = bcrypt.generate_password_hash(password).decode('utf-8')
        db.session.commit()

        db.session.delete(reset_id_object)
        db.session.commit()

        flash("Password changed successfully. Login", "success")
        return redirect(url_for("login"))

    return render_template("reset_password.html")



if __name__ == "__main__":
    app.run(debug=True)