from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField,PasswordField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditorField


# WTForm for creating a blog post
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


# TODO: Create a RegisterForm to register new users
class Registerform(FlaskForm):
    name = StringField("name",validators=[DataRequired()])
    email = StringField("email",validators=[DataRequired()])
    password = PasswordField("password",validators=[DataRequired()])
    submit = SubmitField("register me")

# TODO: Create a LoginForm to login existing users
class Loginform(FlaskForm):
    email = StringField("email",validators=[DataRequired()])
    password = PasswordField("password",validators=[DataRequired()])
    submit = SubmitField("let me in")

# TODO: Create a CommentForm so users can leave comments below posts
class CommentForm(FlaskForm):
    text = CKEditorField("comment",validators=[DataRequired()])
    submit = SubmitField("submit")