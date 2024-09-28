from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash,request,session
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user,login_required
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, Text,ForeignKey
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import os

# Import your forms from the forms.py
from forms import CreatePostForm
from forms import Registerform
from forms import Loginform
from forms import CommentForm

from dotenv import load_dotenv
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("secret_key")
ckeditor = CKEditor(app)
bootstrap = Bootstrap5(app)

# TODO: Configure Flask-Login


# CREATE DATABASE
class Base(DeclarativeBase):
    pass
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("db_uri",'sqlite:///posts.db')
db = SQLAlchemy(model_class=Base)
db.init_app(app)

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(200), unique=True)
    password: Mapped[str] = mapped_column(String(200))
    name: Mapped[str] = mapped_column(String(200))

    posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment",back_populates="comment_author")
# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_pos"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="posts")
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(Text, nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)

    comments = relationship("Comment", back_populates="parent_post")

    # author: Mapped[str] = mapped_column(String(250), nullable=False)
# TODO: Create a User table for all your registered users. 


class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id: Mapped[int] = mapped_column(Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
    
    #***************Child Relationship*************#
    post_id: Mapped[str] = mapped_column(Integer, db.ForeignKey("blog_pos.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    text: Mapped[str] = mapped_column(Text, nullable=False)

with app.app_context():
    db.create_all()

login_manager = LoginManager()
login_manager.init_app(app)

# User loader function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user is authenticated
        if not current_user.is_authenticated:
            # If not authenticated, abort with a 403 error or redirect to login
            return abort(403)  # You could also redirect to the login page

        # If authenticated but not an admin (id != 1), abort with a 403 error
        if current_user.id != 1:
            return abort(403)

        # Otherwise, the user is an admin, continue with the route function
        return f(*args, **kwargs)
    
    return decorated_function

# TODO: Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register',methods = ["GET","POST"])
def register():
    form = Registerform()
    all_users = User.query.all()
    email_list = [user.email for user in all_users]
    if form.validate_on_submit():
    
        name = request.form.get("name")
        email = request.form.get("email")
        password_ = request.form.get("password")
        password = generate_password_hash(password_, method='scrypt', salt_length=3)

        if email not in email_list:
            new_user = User(
            email = email,
            name = name,
            password = password
            )
            db.session.add(new_user)
            db.session.commit()
            session["logged_out"] = False
            return render_template("index.html",)
        else:
            flash("you have already register, try login instead")
            return redirect(url_for('login'))
            
    return render_template("register.html",form = form)


# TODO: Retrieve a user from the database based on their email. 
@app.route('/login',methods = ["GET","POST"])
def login():
    form = Loginform()
    if form.validate_on_submit():
        email = request.form.get("email")
        password_ = request.form.get("password")

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password_):
                login_user(user)
                session['logged_out'] = False
                if user.email == os.getenv("admin_email"):
                    session['admin'] = True
                    return redirect(url_for("get_all_posts"))
                else:
                    session['admin'] = False
                    return redirect(url_for("get_all_posts"))
            else:
                flash("password is incorrect")
                return redirect(url_for("login",form = form))
        else:
            flash("this email does not exist")
            return redirect(url_for("login"))    
    return render_template("login.html",form = form)


@app.route('/logout')
def logout():
    logout_user()
    session["logged_out"] = True
    return render_template("index.html",logged_out = True)




@app.route('/')
def get_all_posts():
    logged_out = session.get('logged_out', True)
    admin = session.get('admin', False)
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts,logged_out = logged_out,admin = admin)


# TODO: Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>",methods = ["GET","POST"])
def show_post(post_id):
    form = CommentForm()  
    requested_post = db.get_or_404(BlogPost, post_id)
    if form.validate_on_submit():
        new_comment = Comment(
            text = form.text.data,
            author_id = current_user.id,
            post_id=post_id
        )
        db.session.add(new_comment)
        db.session.commit()
    return render_template("post.html", post=requested_post,form = form)


# TODO: Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])

def add_new_post():
    form = CreatePostForm()
    if current_user.is_authenticated:
        author_id = current_user.id
    else:
    # Handle the case where the user is not logged in
        flash("You need to be logged in to create a post.")
        return redirect(url_for('login'))
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author_id = current_user.id,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


# TODO: Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug = True)
