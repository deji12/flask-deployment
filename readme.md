# Full Flask Authentication Tutorial (Login, Register, Logout & Reset Password)

This tutorial will teach you about authentication and registration in Flask.

## Getting Started

### 1. Project Setup

- Create and enter the desired directory for project setup.

- Create a virtual environment using `pipenv` or other means:
    - Install 
        ```bash
        pip install pipenv
        ```
    - Create & activate virtual environment:
        ```bash
        pipenv shell
        ```
    - Deactivate:
        ```bash
        exit
        ```
    - To reactivate, navigate in terminal to the virtual environment location and run:
        ```bash
        pipenv shell
        ```

- Install Flask & SQLAlchemy:

    ```shell
    pip install Flask Flask-SQLAlchemy
    ```

### 2. Environment Variables & Flask Configuration

- Set Flask environment variables
    - Windows (powershell):
        ```bash 
        setx FLASK_APP app.py
        ```

    - Mac/Linux:
        ```bash
        export FLASK_APP=app.py
        ```

- Install python decouple:
    ```bash
    pip install python-decouple
    ```

- Create `.env` file:
    ```bash
    FLASK_APP=app.py
    SECRET_KEY=super-secret-key
    DATABASE_URL=sqlite:///auth.db
    ```

- Next, create `config.py` and load environment variables:
    ```python
    from decouple import config

    class Config:
        SECRET_KEY = config("SECRET_KEY")
        SQLALCHEMY_DATABASE_URI = config("DATABASE_URL")
    ```

### 3. Create Application (`app.py`)

- Create file `app.py`

- Initialize flask app:
    ```python
    from flask import Flask
    from config import Config

    app = Flask(__name__)
    app.config.from_object(Config)

    
    # Views & logic here
    

    if __name__ == "__main__":
        app.run(debug=True)
    ```

- Create first view:

    ```python
    @app.route("/")
    def home():
        return "<p>Hello, world!</p>"
    ```

- Run application:

    - Using flask run:
        ```bash
        flask run
        ```
    - Or (In location of where `app.py` is):
        ```bash
        python app.py
        ```

### 4. Creating Models

- Create `models.py` file
- Make requied imports:
    ```python
    from flask_sqlalchemy import SQLAlchemy
    from datetime import datetime, timedelta, timezone
    import uuid
    ```

- Inistaise sql alchemy:
    ```python
    db = SQLAlchemy()
    ```

- User model:

    ```python
    class User(db.Model, UserMixin):
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(100), unique=True, nullable=False)
        email = db.Column(db.String(50), unique=True, nullable=False)
        password = db.Column(db.String(200), nullable=False)

        password_reset_ids = db.relationship(
            "PasswordResetId",
            backref="user",
            cascade="all, delete-orphan"
        )
    ```
- Password Reset Id model:
    ```python
    class PasswordResetId(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

        reset_id = db.Column(
            db.String(36),
            nullable=False,
            default=lambda: str(uuid.uuid4())
        )

        created_at = db.Column(
            db.DateTime(timezone=True),
            default=lambda: datetime.now(timezone.utc),
            nullable=False
        )

        def is_expired(self):
            expires_at = self.created_at + timedelta(minutes=10)
            return datetime.now(timezone.utc) > expires_at
    ```

### 5. Database Migration Setup

- Install flask migrate:
    ```bash
    pip install flask-migrate
    ```

- Make required imports and initialize db in app
    ```python
    from flask import Flask
    from config import Config

    # imports
    from flask_migrate import Migrate
    from models import db, User, PasswordResetId 

    app = Flask(__name__)
    app.config.from_object(Config)

    db.init_app(app)

    
    # Views & logic here
    

    if __name__ == "__main__":
        app.run(debug=True)
    ```


- Initialize flask migrate in app:
    ```python
    app = Flask(__name__)
    app.config.from_object(Config)
    
    migrate = Migrate(app, db) # <- flask migrate initialization 
    ```

- Next, we need to initialize migrations:
    ```bash
    flask db init
    ```

- Create migrations:
    ```bash
    flask db migrate
    ```

- Apply migrations:
    ```bash
    flask db upgrade
    ```

### 6. Setup Template & Static Files

- Create `templates` and `static/css` folders

- Download the following HTML templates from GitHub:
     - `styles.css`
     - `home.html`
     - `login.html`
     - `register.html`
     - `forgot_password.html`
     - `reset_password.html`

- Move these files to the templates and static folders

### 7. Create `base.html` for Templates

- Observe that all `html` files have same repeating structure. We will create a `base.html` file to prevent repeating ourselves multiple times. 

- Create a `base.html` file in templates and add the following:
    ```html
    <!DOCTYPE html>
        <html lang="en" dir="ltr">
        <head>
            <meta charset="utf-8">
            <title>Auth system</title>
            <link rel="stylesheet" href="styles.css">
        </head>
        <body>
            <div class="center">

                <!-- Flash message goes here -->

                {% block content %}

                {% endblock content %}
            </div>

        </body>
    </html>
    ```

- Connect to static file:
    - replace `styles.css` with:
    ```html
    {{ url_for('static', filename='css/style.css') }}
    ```

- Return an html file in home view:
    ```python
    @app.route("/")
    def home():
        return render_template("home.html")
    ```

- Now we can extend `base.html` in other files

### 8. Create Register & Login Boilerplate Code

- In `app.py`:
    ```python
    @app.route("/register", methods=["GET", "POST"])
    def register():
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        return render_template("login.html")
    ```

### 9. Working on Register View

- Make required imports:
    ```python
    from flask import Flask, render_template, request, url_for, redirect, flash
    from sqlalchemy import select
    ```

- In `register.html`, extend from `base.html`, give input fields a name attribute, and set login link to point to login view :
    ```html
    {% extends 'base.html' %}
    {% block content %}

        <h1>Register</h1>
        <form method="POST">
            <div class="txt_field">
                <input type="text" name="username" required>
                <span></span>
                <label>Username</label>
            </div>
            <div class="txt_field">
                <input type="email" name="email" required>
                <span></span>
                <label>Email</label>
                </div>
            <div class="txt_field">
                <input type="password" name="password" required>
                <span></span>
                <label>Password</label>
            </div>    
            <div class="txt_field">
                <input type="password" name="confirm_password" required>
                <span></span>
                <label>Confirm Password</label>
            </div>    
            <input type="submit" value="Register">
            <div class="signup_link">
                Already have an account? <a href="{{ url_for('login') }}">Login</a>
            </div>
        </form>
        
    {% endblock content %}
    ```

- In register view, Check for incoming form submission and grab the form data
    ```python
    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":

            # grab form data
            username = request.form.get("username")
            email = request.form.get("email")
            password = request.form.get("password")
            confirm_password = request.form.get("confirm_password")

        return render_template("register.html")
    ```

- Vaidate the data:
    ```python
    if len(password) < 5:
        flash("Password must be at least 5 characters", "error")
        return redirect(url_for("register"))

    # # make sure email and username are not being used
    if db.session.scalar(
        select(User).where(User.email == email)
    ):
        flash("Email already in use", "error")
        return redirect(url_for("register"))

    if db.session.scalar(
        select(User).where(User.username == username)
    ):
        flash("Email already in use", "error")
        return redirect(url_for("register"))
    ```

- If there are no errors, we will need to hash passwords before saving:
    - Install bcrypt:
        ```bash
        pip install Flask-Bcrypt
        ```

    - Import bcrypt:
        ```python
        from flask_bcrypt import Bcrypt
        ```

    - Initialize bcrypt:
        ```python
        bcrypt = Bcrypt(app)
        ```

- Generate password hash:
    ```python
    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    ```

- Create user:
    ```python
    user = User(
        username = username, 
        email = email, 
        password = hashed_password
    )
    db.session.add(user)
    db.session.commit()

    flash("Account created successfully", "success")
    return redirect(url_for("login"))
    ```

### 10. Displayig Flash Messages

- We will display the flash messages in `base.html` since all files will extend it:
    ```html
    <!-- Flash message goes here -->

    {% with messages = get_flashed_messages(with_categories=true) %}
        {% if messages  %}
            {% for category, message in messages  %}
                <center>
                    <h4
                        {% if category == "error" %}
                            style="color: firebrick"
                        {% else %}
                            style="color: dodgerblue"
                        {% endif %}
                    >
                        {{message}}
                    </h4>
                </center>
            {% endfor %}
        {% endif %}
    {% endwith %}
    ```

- Test code to see if users can now register

### 11. Setup Flask Login
- Head to documentation: https://flask-login.readthedocs.io/en/latest/

- Replace:
    ```python
    @login_manager.user_loader
    def load_user(user_id):
        return User.get(user_id)
    ```
- With this:
    ```python
    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))
    ```

- After setting `login_view`, try to access home page without authentication

### 12. Working on Login View

- In `login.html`, extend from `base.html`, give input fields a name attribute, and set register link to point to register view:
    ```html
    {% extends 'base.html' %}

    {% block content %}

        <h1>Login</h1>
        <form method="POST">
            <div class="txt_field">
                <input type="text" required name="username">
                <span></span>
                <label>Username</label>
            </div>
            <div class="txt_field">
                <input type="password" required name="password"> 
                <span></span>
                <label>Password</label>
            </div>
            <input type="submit" value="Login">
            <div class="signup_link">
                Not a member? <a href="{{ url_for('register') }}">Signup</a>
                <p>Forgot your Password? <a href="#">Reset Password</a></p> 
            </div>
        </form>

    {% endblock content %}
    ```

- Make required imports:
    ```python
    from flask_login import login_user
    ```

- In register view, Check for incoming form submission and grab the form data:
    ```python
    @app.route("/login", methods=["GET", "POST"])
    def login():

        if request.method == 'POST':
            username = request.form.get("username")
            password = request.form.get("password")

        return render_template("login.html")
    ```

- Authenticate the user details:
    ```python
    user = db.session.scalar(
        select(User).where(User.username == username)
    )
    if user:
        # determine if password is correct
        if bcrypt.check_password_hash(user.password, password):
            login_user(user)

            next = flask.request.args.get('next')
           return flask.redirect(next or url_for('home'))
        
        flash("Invalid password entered", "error")
        return redirect(url_for("login"))
        
    flash("Invalid username entered", "error")
    return redirect(url_for("login"))
    ```

- Test if users can login
- Render out authenticated user's username in `home.html`:
    ```html
    <P>Hello, {{ current_user.username }}! </P>
    ```


### 13. Logout View

- Import `logout_user`:
    ```python
    from flask_login import logout_user
    ```

- Create logout view:
    ```python
    @app.route('/logout', methods=['GET'])
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('login'))
    ```

- Connect logout url in `home.html` to logout view:
    ```html
    <a href="{{ url_for('logout') }}">Logout</a>
    ```

- Test logout functionality

### 14. Create `forgot_password` and `reset_password` views:

- Views:
    ```python
    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password():
        return render_template("forgot_password.html", reset_sent=False)

    @app.route("/reset-password/<reset_id>", methods=["GET", "POST"])
    def reset_password(reset_id):
        return render_template("reset_password.html")
    ```

### 15. Working on Forgot Password View

- In `forgot_password.html`, extend from `base.html`, give input field a `name` attribute, and conditionally render components depending on `reset_sent`:

    ```html
    {% extends 'base.html' %}

    {% block content %}

        <h1>Reset Password</h1>

        {% if reset_sent %}
            <div class="signup_link">A password reset link has been sent to your email and is valid for <b>10 minutes</b></div>
            <form method="POST">
                <div class="txt_field" hidden>
                    <input type="email" name="email" required value="{{email}}">
                    <span></span>
                    <label>Email</label>
                </div>
                <div class="signup_link">
                    Didn't receive email?
                </div>
                <input type="submit" value="Resend Email">
                <br>
            </form>

        {% else %}
            <div class="signup_link">Enter your email to reset password</div>
            <form method="POST">
                <div class="txt_field">
                    <input type="email" name="email" required>
                    <span></span>
                    <label>Email</label>
                </div>
                <input type="submit" value="Reset Password">
                <div class="signup_link">
                    Not a member? <a href="{{ url_for('register') }}">Signup</a>
                    <p>Remember your Password? <a href="{{ url_for('login') }}">Login</a></p> 
                </div>
            </form>

        {% endif %}

    {% endblock content %}
    ```

- In forgot password view, Check for incoming form submission and grab the form data:
    ```python
    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password():

        if request.method == 'POST':
            email = request.form.get("email")

        return render_template("forgot_password.html", reset_sent=False)
    ```

- Verify if email is valid:
    ```python
    @app.route("/forgot-password", methods=["GET", "POST"])
    def forgot_password():

        if request.method == 'POST':
            email = request.form.get("email")

            user = db.session.scalar(
                select(User).where(User.email == email)
            )

            if not user:
                flash("No user with that email found", "error")
                return redirect(url_for("forgot_password"))

        return render_template("forgot_password.html", reset_sent=False)
    ```

- Setup email settings in `config.py` so we can send password reset email:

    For gmail users, create an app password below:
    `https://myaccount.google.com/apppasswords`
    &nbsp;

    - Add email credentials to `.env`:
        ```env
        MAIL_SERVER=smtp.gmail.com
        MAIL_PORT=587
        MAIL_USE_TLS=True
        MAIL_USE_SSL=False
        MAIL_USERNAME=yourGoogleAccount@gmail.com
        MAIL_PASSWORD=yourGmailPassword
        MAIL_DEFAULT_SENDER_NAME=yourName
        ```

    - Add mail credentials to `config.py`:
        ```python
        from decouple import config
        
        class Config:
            SECRET_KEY = config("SECRET_KEY")
            SQLALCHEMY_DATABASE_URI = config("DATABASE_URL")

            MAIL_SERVER = config("MAIL_SERVER")
            MAIL_PORT = config("MAIL_PORT", cast=int)
            MAIL_USE_TLS = config("MAIL_USE_TLS", cast=bool)
            MAIL_USE_SSL = config("MAIL_USE_SSL", cast=bool)
            MAIL_USERNAME = config("MAIL_USERNAME")
            MAIL_PASSWORD = config("MAIL_PASSWORD")
            MAIL_DEFAULT_SENDER_NAME = config("MAIL_DEFAULT_SENDER_NAME")
            MAIL_DEFAULT_SENDER = f"{MAIL_DEFAULT_SENDER_NAME} <{MAIL_USERNAME}>" # "Name <youremail@gmail.com>"
        ```

- Install & Setup Flask mail

    - Install:
        ```bash
        pip install Flask-Mail
        ```
    - Import and initialize:
        ```python
        from flask_mail import Mail, Message

        mail = Mail(app)
        ```

- In `app.py`, delete old reset_id's and create a new one for user:

    ```python
    # delete other potentially existing codes
    user.password_reset_ids.clear()
    
    new_password_reset_id = PasswordResetId(user=user)
    db.session.add(new_password_reset_id)
    db.session.commit()
    ```

- Generate password reset link:
    ```python
    password_reset_link = url_for("reset_password", reset_id=new_password_reset_id.reset_id , _external=True)
    ```

- Send email:
    ```python
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
    ```

### 16. Password Reset View

- In `reset_password.html`, extend from `base.html` and give input field a `name` attribute:
    ```html
    {% extends 'base.html' %}

    {% block content %}

        <h1>Reset Password</h1>
                
        <form method="POST">
            <div class="txt_field">
                <input type="password" name="password" required>
                <span></span>
                <label>Password</label>
            </div>    

            <div class="txt_field">
                <input type="password" name="confirm_password" required>
                <span></span>
                <label>Confirm Password</label>
            </div>    

            <input type="submit" value="Register">
            <div class="signup_link">
                Remember your password? <a href="{{ url_for('login') }}">Login</a>
            </div>
        </form>

    {% endblock content %}
    ```

- Make sure that reset_id is valid:
    ```python
    @app.route("/reset-password/<reset_code>", methods=["GET", "POST"])
    def reset_password(reset_code):

        reset_id = db.session.scalar(
            select(PasswordResetId).where(PasswordResetId.reset_id == reset_code)
        )

        if not reset_id:
            flash("Invalid reset link", "error")
            return redirect(url_for("forgot_password"))

        # delete reset id of it has expired
        if reset_id.is_expired():
            db.session.delete(reset_id)
            db.session.commit()

            flash("Expired reset link", "error")
            return redirect(url_for("forgot_password"))

        return render_template("reset_password.html")
    ```

- Check for incomimg post request and grab form data:
    ```python
    if request.method == "POST":

        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
    ```

- Verify passwords:
    ```python
    if len(password) < 5:
        flash("Password must be at east 5 characters long", "error")
        return redirect(url_for("reset_password"))

    if password != confirm_password:
        flash("Passwords do not match", "error")
        return redirect(url_for("reset_password"))
    ```

- Next, update user password:
    ```python
    user = reset_id.user
    user.password = bcrypt.generate_password_hash(password).decode('utf-8')
    db.session.commit()
    ```

- Delete reset id after use and redirect to login page:
    ```python
    db.session.delete(code)
    db.session.commit()
    
    flash("password changed successfully. Login", "success")
    return redirect(url_for("login"))
    ```

- Test password reset feature

### 17. Restrict Authenticated Users From Auth Pages:

- Import `current_user`:
    ```python
    from flask_login import current_user
    ```

- Prevent authenticated user from visiting register, login, forgot password, and reset password pages:

    ```python
    if current_user.is_authenticated:
        return redirect(url_for("home"))
    ```

- Test the code