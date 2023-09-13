import datetime
import hashlib
import os
import bcrypt

import base64
import boto3
import datetime
import io
from io import BytesIO
from mimetypes import guess_extension, guess_type
from PIL import Image
import random
import re
import string

from flask_sqlalchemy import SQLAlchemy



db = SQLAlchemy()

# your classes here

association_table_user_users = db.Table(
    "user_users",
    db.Column("user_id", db.Integer, db.ForeignKey("user.id")),
    db.Column("user_id", db.Integer, db.ForeignKey("user.id")),
)


# User model class

class User(db.Model):
    """
    User model
    Many-to-many relationship w/ other users
    One-to-many relationship w/ posts (one user can have many posts)
    One-to-many relationship w/ buckets (one user can have many buckets)
    """
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    # User information
    email = db.Column(db.String, nullable=False, unique=True)
    password_digest = db.Column(db.String, nullable=False)
    username = db.Column(db.String, nullable=False)
    name = db.Column(db.String, nullable=False)

    posts = db.relationship("Posts", backref="posts", cascade="delete")
    buckets = db.relationship("Bucket", backref="bucket", cascade="delete")
    followed_users = db.relationship("User", secondary=association_table_user_users, backref="user")

    # Session information
    session_token = db.Column(db.String, nullable=False, unique=True)
    session_expiration = db.Column(db.DateTime, nullable=False)
    update_token = db.Column(db.String, nullable=False, unique=True)

    def __init__(self, **kwargs):
        """
        Initializes a User object
        """
        self.email = kwargs.get("email")
        self.password_digest = bcrypt.hashpw(kwargs.get("password").encode("utf8"), bcrypt.gensalt(rounds=13))
        self.username = kwargs.get("username")
        self.name = kwargs.get("name")
        self.renew_session()

    def _urlsafe_base_64(self):
        """
        Randomly generates hashed tokens (used for session/update tokens)
        """
        return hashlib.sha1(os.urandom(64)).hexdigest()

    def renew_session(self):
        """
        Renews the sessions, i.e.
        1. Creates a new session token
        2. Sets the expiration time of the session to be a day from now
        3. Creates a new update token
        """
        self.session_token = self._urlsafe_base_64()
        self.session_expiration = datetime.datetime.now() + datetime.timedelta(days=1)
        self.update_token = self._urlsafe_base_64()

    def verify_password(self, password):
        """
        Verifies the password of a user
        """
        return bcrypt.checkpw(password.encode("utf8"), self.password_digest)

    def verify_session_token(self, session_token):
        """
        Verifies the session token of a user
        """
        return session_token == self.session_token and datetime.datetime.now() < self.session_expiration

    def verify_update_token(self, update_token):
        """
        Verifies the update token of a user
        """
        return update_token == self.update_token
    
    def serialize(self):
        """
        Serializes a User object
        """
        return {
            "id": self.id,
            "email": self.email,
            "username": self.username,
            "name": self.name,
            "posts": [p.simple_serialize() for p in self.posts],
            "buckets": [b.serialize() for b in self.buckets],
            "followed_users": [u.simple_serialize() for u in self.followed_users]
        }    
    
    def simple_serialize(self):
        """
        Serializes a User object using only id and email
        """
        return {
            "id": self.id,
            "email": self.email,
            "username": self.username,
            "name": self.name
        }    

    def posts_serialize(self):
        """
        Serializes a User object using only id and posts
        """
        return {
            "id": self.id,
            "posts": [p.simple_serialize() for p in self.posts]
        }

    def buckets_serialize(self):
        """
        Serializes a User object using only id and buckets
        """
        return {
            "id": self.id,
            "buckets": [b.serialize() for b in self.buckets]
        }    

    def followed_users_serialize(self):
        """
        Serializes a User object using only id and followed users
        """
        return {
            "id": self.id,
            "following": [u.simple_serialize() for u in self.followed_users]
        }

# Post model class

class Posts(db.Model):
    """
    Posts model
    One-to-many relationship w/ comments (one post can have many comments)
    """
    __tablename__ = "posts"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    message = db.Column(db.String, nullable=False)
    date = db.Column(db.String, nullable=False)
    saved = db.Column(db.Boolean, nullable=False)
    saved_count = db.Column(db.Integer, nullable=False)
    liked = db.Column(db.Boolean, nullable=False)
    liked_count = db.Column(db.Integer, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    email = db.Column(db.String, nullable=False)
    username = db.Column(db.String, nullable=False)
    name = db.Column(db.String, nullable=False)

    asset = db.relationship("Asset", backref="assets", cascade="delete")
    comments = db.relationship("Comments", backref="posts", cascade="delete")


    def __init__(self, **kwargs):
        """
        Initializes a Posts object
        """
        self.message = kwargs.get("message")
        self.date = datetime.datetime.now()
        self.saved = False
        self.saved_count = 0
        self.liked = False
        self.liked_count = 0
        self.user_id = kwargs.get("user_id")
        self.email = kwargs.get("email")
        self.username = kwargs.get("username")
        self.name = kwargs.get("name")



    def serialize(self):
        """
        Serializes a Posts object
        """
        return {
            "id": self.id,
            "email": self.email,
            "username": self.username,
            "name": self.name,
            "message": self.message,
            "date": self.date,
            "saved": self.saved,
            "saved_count": self.saved_count,
            "liked": self.liked,
            "liked_count": self.liked_count,
            "asset": [a.serialize() for a in self.asset],
            "comments":    [c.serialize() for c in self.comments]
        }
    
    def simple_serialize(self):
        """
        Serialize a Posts object without "comments"
        """
        return {
            "id": self.id,
            "message": self.message,
            "date": self.date,
            "saved": self.saved,
            "saved_count": self.saved_count,
            "liked": self.liked,
            "liked_count": self.liked_count,
        }

# Comments model class

class Comments(db.Model):
    """
    Comments model
    """

    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    message = db.Column(db.String, nullable=False)
    date = db.Column(db.String, nullable=False)

    post_id = db.Column(db.Integer, db.ForeignKey("posts.id"), nullable=False)

    def __init__(self, **kwargs):
        """
        Initializes a Comments object
        """
        self.message = kwargs.get("message")
        self.date = datetime.datetime.now()
        self.post_id = kwargs.get("post_id")

    def serialize(self):
        """
        Serializes a Comments object
        """
        return {
            "id": self.id,
            "message": self.message,
            "date": self.date,
            "post_id": self.post_id
        }
    
    
# Bucket model class

class Bucket(db.Model):
    """
    Bucket (list) model
    """
    __tablename__ = "bucket"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    message = db.Column(db.String, nullable=False)
    checked = db.Column(db.Boolean, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    def __init__(self, **kwargs):
        """
        Initializes an Bucket object
        """
        self.message = kwargs.get("message")
        self.checked = False
        self.user_id = kwargs.get("user_id")

    def serialize(self):
        """
        Serializes a Bucket object
        """
        return {
            "id": self.id,
            "message": self.message,
            "checked": self.checked
        }
    
# Asset class (for images)

EXTENSIONS = ["png", "gif", "jpg", "jpeg"]
BASE_DIR = os.getcwd()
S3_BUCKET_NAME = os.environ.get("S3_BUCKET_NAME")
S3_BASE_URL = f"https://{S3_BUCKET_NAME}.s3.us-east-1.amazonaws.com"

class Asset(db.Model):
    """
    Asset model
    """

    __tablename__ = "assets"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    base_url = db.Column(db.String, nullable=True)
    salt = db.Column(db.String, nullable=False)
    extension = db.Column(db.String, nullable=False)
    width = db.Column(db.Integer, nullable=False)
    height = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False)

    post_id = db.Column(db.Integer, db.ForeignKey("posts.id"), nullable=False)

    def __init__(self, **kwargs):
        """
        Initializes an Asset object
        """
        self.create(kwargs.get("image_data"))
        self.post_id = kwargs.get("post_id")

    def serialize(self):
        """
        Serializes an Asset object
        """

        return {
            "url": f"{self.base_url}/{self.salt}.{self.extension}",
            "created_at": str(self.created_at)
        }

    def create(self, image_data):
        """
        Given an image in base64 form, does the following:
            1. Rejects the image if it's not supported filetype
            2. Generates a random string for the image filename
            3. Decodes the image and attempts to upload it to AWS
        """

        try:
            ext = guess_extension(guess_type(image_data)[0])[1:]

            # Only accept support file extension
            if ext not in EXTENSIONS:
                raise Exception(f"Extension {ext} not supported")
            
            # Securely generate a random string for image name
            salt = "".join(
                random.SystemRandom().choice(
                    string.ascii_uppercase + string.digits
                )
                for _ in range(16)
            )

            # Remove base64 header
            img_str = re.sub("^data:image/.+;base64,", "", image_data)
            img_data = base64.b64decode(img_str)
            img = Image.open(BytesIO(img_data))

            self.base_url = S3_BASE_URL
            self.salt = salt
            self.extension = ext
            self.width = img.width
            self.height = img.height
            self.created_at = datetime.datetime.now()

            img_filename = f"{self.salt}.{self.extension}"
            self.upload(img, img_filename)
        
        except Exception as e:
            print(f"Error While creating image: {e}")

    
    def upload(self, img, img_filename):
        """
        Attempt to upload the image into S3 bucket
        """

        try:
            # Save image temporarily on the server
            img_temploc = f"{BASE_DIR}/{img_filename}"
            img.save(img_temploc)
            
            # Upload the image to S3
            s3_client = boto3.client("s3")
            s3_client.upload_file(img_temploc, S3_BUCKET_NAME, img_filename)

            # Make s3 image url public
            s3_resource = boto3.resource("s3")
            object_acl = s3_resource.ObjectAcl(S3_BUCKET_NAME, img_filename)
            object_acl.put(ACL="public-read")

            # Remove image from server
            os.remove(img_temploc)

        except Exception as e:
            print(f"Error while uploading image: {e}")