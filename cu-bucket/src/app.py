import json
import datetime

from db import db
from flask import Flask, request
from db import Posts
from db import Comments
from db import Bucket
from db import User
from db import Asset
import os
import users_dao

app = Flask(__name__)
db_filename = "cubucket.db"

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///%s" % db_filename
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True

db.init_app(app)
with app.app_context():
    db.create_all()

# generalized response formats
def success_response(data, code=200):
    return json.dumps(data), code

def failure_response(message, code=404):
    return json.dumps({"error": message}), code

# Helper function for user token

def extract_token(request):
    """
    Helper function that extracts the token from the header of a request
    """
    auth_header = request.headers.get("Authorization")

    if auth_header is None:
        return False, json.dumps({"error": "Missing auth header"})

    bearer_token = auth_header.replace("Bearer","").strip()

    if not bearer_token:
        return False, json.dumps({"error": "Invalid auth header"})
    
    return True, bearer_token


# -- USER ROUTES ---------------------------------------------

@app.route("/api/register/", methods=["POST"])
def register_account():
    """
    Endpoint for registering a new user
    """
    body = json.loads(request.data)
    email = body.get("email")
    password = body.get("password")
    username = body.get("username")
    name = body.get("name")

    if email is None or password is None or username is None or username is None:
        return failure_response("Email, password, username, or name is missing")
    
    created, user = users_dao.create_user(email, password, username, name)
    
    if not created:
        return failure_response("User already exists!")
    
    return success_response({
        "session_token": user.session_token,
        "session_expiration": str(user.session_expiration),
        "update_token": user.update_token}
    )


@app.route("/api/login/", methods=["POST"])
def login():
    """
    Endpoint for logging in a user
    """
    body = json.loads(request.data)
    email = body.get("email")
    password = body.get("password")

    if email is None or password is None:
            return json.dumps({"error": "Invalid email or password"}), 400
    
    success, user = users_dao.verify_credentials(email, password)

    if not success:
        return json.dumps({"error": "Incorrect email or password"}), 400
    
    return json.dumps({
        "session_token": user.session_token,
        "session_expiration": str(user.session_expiration),
        "update_token": user.update_token
    })


@app.route("/api/session/", methods=["POST"])
def update_session():
    """
    Endpoint for updating a user's session
    """
    success, update_token = extract_token(request)

    if not success:
        return update_token
    
    user = users_dao.renew_session(update_token)

    if user is None:
        return json.dumps({"error": "Invalid update token"})
    
    return json.dumps({
        "session_token": user.session_token,
        "session_expiration": str(user.session_expiration),
        "update_token": user.update_token
    })


@app.route("/api/secret/", methods=["POST"])
def secret_message():
    """
    Endpoint for verifying a session token and returning a secret message

    In your project, you will use the same logic for any endpoint that needs 
    authentication
    """
    success, session_token = extract_token(request)

    if not success:
        return session_token
    
    user = users_dao.get_user_by_session_token(session_token)

    if user is None or not user.verify_session_token(session_token):
        return json.dumps({"error": "Invalid session token"})
    
    return json.dumps({"message": "Wow we implemented session token!"}), 200


@app.route("/api/logout/", methods=["POST"])
def logout():
    """
    Endpoint for logging out a user
    """
    success, session_token = extract_token(request)

    if not success:
        return session_token
    
    user = users_dao.get_user_by_session_token(session_token)

    if not user or not user.verify_session_token(session_token):
        return json.dumps({"error": "Invalid session token"}), 400
    
    user.session_expiration = datetime.datetime.now()
    db.session.commit()

    return json.dumps({"message": "User has successfully logged out"})


@app.route("/api/users/")
def get_users():
    """
    Endpoint for getting all users
    """
    users = [user.serialize() for user in User.query.all()]
    return success_response({"users": users})


@app.route("/api/users/<int:user_id>/")
def get_user(user_id):
    """
    Endpoint for getting user by id
    """
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return failure_response("User not found!")
    return success_response(user.serialize())

@app.route("/api/users/<int:user_id>/posts/")
def get_user_posts(user_id):
    """
    Endpoint for getting a posts by user id
    """
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return failure_response("User not found!")
    return success_response(user.posts_serialize())


@app.route("/api/users/<int:user_id>/buckets/")
def get_user_buckets(user_id):
    """
    Endpoint for getting a buckets by user id
    """
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return failure_response("User not found!")
    return success_response(user.buckets_serialize())


@app.route("/api/users/<int:user_id>/following/")
def get_user_users(user_id):
    """
    Endpoint for getting followed users by user id
    """
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return failure_response("User not found!")
    return success_response(user.followed_users_serialize())


# -- POSTS ROUTES ---------------------------------------------

@app.route("/api/posts/")
def get_posts():
    """
    Endpoint for getting all posts
    """
    posts = [post.serialize() for post in Posts.query.all()]
    return success_response({"posts": posts})


@app.route("/api/users/<int:user_id>/posts/", methods=["POST"])
def create_post(user_id):
    """
    Endpoint for creating a new post with a user's id
    """
    user = User.query.filter_by(id=user_id).first()
    if user is None:
        return failure_response("User not found!")

    body = json.loads(request.data)
    new_post = Posts(
        message = body.get("message"),
        date = datetime.datetime.now(),
        user_id = user_id,
        email = user.email,
        username = user.username,
        name = user.name
    )

    if new_post.message is None:
        return failure_response("Missing message", 400)
    
    db.session.add(new_post)
    db.session.commit()
    return success_response(new_post.serialize(), 201)


@app.route("/api/posts/<int:post_id>/")
def get_post(post_id):
    """
    Endpoint for getting a post by id
    """
    post = Posts.query.filter_by(id=post_id).first()
    if post is None:
        return failure_response("Post not found!")
    return success_response(post.serialize())


@app.route("/api/posts/<int:post_id>/saved/", methods=["POST"])
def save_post(post_id):
    """
    Endpoint for saving a post (updates a posts's saved property to True/False)
    """
    post = Posts.query.filter_by(id=post_id).first()
    if post is None:
        return failure_response("Post not found!")
    
    body = json.loads(request.data)
    user_decision = bool(body.get('saved'))

    if post.saved is False and user_decision is True:
        post.saved_count = post.saved_count + 1
        post.saved = True

    if post.saved is True and user_decision is False:
        post.saved_count = post.saved_count - 1
        post.saved = False
    
    db.session.commit()
    return success_response(post.serialize())


@app.route("/api/posts/<int:post_id>/likes/", methods=["POST"])
def like_post(post_id):
    """
    Endpoint for liking a post (adds a like to a post if not liked already)
    """
    post = Posts.query.filter_by(id=post_id).first()
    if post is None:
        return failure_response("Post not found!")

    body = json.loads(request.data)
    user_decision = bool(body.get('liked'))
    
    if post.liked is False and user_decision is True:
        post.liked_count = post.liked_count + 1
        post.liked = True

    if post.liked is True and user_decision is False:
        post.liked_count = post.liked_count - 1
        post.liked = False
    
    db.session.commit()
    return success_response(post.serialize())


@app.route("/api/posts/<int:post_id>/", methods=["DELETE"])
def delete_post(post_id):
    """
    Endpoint for deleting a post by id
    """
    post = Posts.query.filter_by(id=post_id).first()
    if post is None:
        return failure_response("Post not found!")
    db.session.delete(post)
    db.session.commit()
    return success_response(post.serialize()) 


# # -- COMMENTS ROUTES ------------------------------------------------


@app.route("/api/posts/<int:post_id>/comments/", methods=["POST"])
def create_comment(post_id):
    """
    Endpoint for creating a comment
    """
    post = Posts.query.filter_by(id=post_id)
    if post is None:
        return failure_response("Post not found!")

    body = json.loads(request.data)
    new_comment = Comments(
        message = body.get("message"),
        date = datetime.datetime.now(),
        post_id = post_id
    )

    if new_comment.message is None:
        return failure_response("Missing message", 400)
    
    db.session.add(new_comment)
    db.session.commit()
    return success_response(new_comment.serialize(), 201)


@app.route("/api/comments/<int:comment_id>/")
def get_comment(comment_id):
    """
    Endpoint for getting a comment by id
    """
    comment = Comments.query.filter_by(id=comment_id).first()
    if comment is None:
        return failure_response("Comment not found!")
    return success_response(comment.serialize())


# # -- BUCKET ROUTES ------------------------------------------

@app.route("/api/buckets/")
def get_buckets():
    """
    Endpoint for getting a user's buckets
    """
    buckets = [bucket.serialize() for bucket in Bucket.query.all()]
    return success_response({"buckets": buckets})

@app.route("/api/users/<int:user_id>/buckets/", methods=["POST"])
def create_bucket(user_id):
    """
    Endpoint for creating a new bucket under a user id
    """
    user = User.query.filter_by(id=user_id)
    if user is None:
        return failure_response("User not found!")
    
    body = json.loads(request.data)
    new_bucket = Bucket(
        message = body.get("message"),
        checked = body.get("checked"),
        user_id = user_id
    )
    if new_bucket.message is None or new_bucket.checked is None:
        return failure_response("Missing message", 400)
    db.session.add(new_bucket)
    db.session.commit()
    return success_response(new_bucket.serialize(), 201)

@app.route("/api/buckets/<int:bucket_id>/", methods=["POST"])
def update_bucket(bucket_id):
    """
    Endpoint for updating a bucket (marks bucket as complete/incomplete)
    """
    bucket = Bucket.query.filter_by(id=bucket_id).first()
    if bucket is None:
        return failure_response("Bucket not found!")

    body = json.loads(request.data)
    user_decision = bool(body.get('checked'))
    
    if bucket.checked is False and user_decision is True:
        bucket.checked = True

    if bucket.checked is True and user_decision is False:
        bucket.checked = False
    
    db.session.commit()
    return success_response(bucket.serialize())

@app.route("/api/buckets/<int:bucket_id>/", methods=["DELETE"])
def delete_bucket(bucket_id):
    """
    Endpoint for deleting a bucket by id
    """
    bucket = Bucket.query.filter_by(id=bucket_id).first()
    if bucket is None:
        return failure_response("Bucket not found!")
    db.session.delete(bucket)
    db.session.commit()
    return success_response(bucket.serialize()) 

# Images routes

@app.route("/upload/<int:post_id>/", methods=["POST"])
def upload(post_id):
    """
    Endpoint for uploading an image to AWS given its base64 form,
    then storing/returning the URL of that image
    """
    body = json.loads(request.data)
    image_data = body.get("image_data")
    if image_data is None:
        return failure_response("No Base64 URL")
    if post_id is None:
        return failure_response("No post id")
    
    # Create new Asset object
    asset = Asset(image_data=image_data, post_id=post_id)
    db.session.add(asset)
    db.session.commit()

    return success_response(asset.serialize(), 201)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
