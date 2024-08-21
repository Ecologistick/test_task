from app import app, db
from app.models import get_fields_names, User, Document
from flask import request
from flask_login import current_user, login_user, logout_user, login_required


@app.errorhandler(401)
def unathorized(e):
    return {"error": "Unauthorized"}


@app.errorhandler(404)
def page_not_found(e):
    return {"error": "Not found"}


@app.errorhandler(405)
def method_not_allowed(e):
    return {"error": "Method not allowed"}


@app.route('/api/login/', methods=["POST"])
def signup_user():
    if current_user.is_authenticated:
        return {"error": "User already logged in"}, 400
    login = request.get_json().get('login')
    password = request.get_json().get('password')

    if login and password:
        user = User.query.filter_by(login=login).first()
        if user is None or not user.check_password(password):
            return {"error": "Invalid data"}, 400
        login_user(user)

        return user.to_dict(), 200
    return {'error': 'Login and password required'}, 422


@app.route('/api/logout/', methods=["POST"])
@login_required
def logout():
    logout_user()
    return {"info": "Logged out. Good bye!"}


@app.route('/api/register/', methods=["POST"])
def register():
    if current_user.is_authenticated:
        return {"error": "User already logged in"}, 400

    raw_data = request.get_json()
    user_id = request.get_json().get('id')
    login = request.get_json().get('login')
    password = request.get_json().get('password')
    sex = request.get_json().get('sex')

    if user_id:
        del raw_data["id"]

    if sex and sex not in {'1', '2'}:
        return {'error': 'Invalid Gender'}, 422

    if login and password:
        del raw_data["password"]

        data = {key: raw_data[key] for key in set(raw_data.keys()) & set(get_fields_names(User))}

        print(data)
        if User.query.filter_by(login=data["login"]).first():
            return {"error": "User with this login already exists"}, 400

        new_user = User(**data)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        return new_user.to_dict()
    return {'error': 'Login and password required'}, 422


@app.route('/api/user/', methods=["GET"])
@login_required
def get_current_user():
    return current_user.to_dict()


@app.route('/api/user/<user_id>/', methods=["GET", "PUT", "DELETE"])
@login_required
def get_or_change_user(user_id):
    user = User.query.get_or_404(user_id)
    user_documents = Document.query.filter_by(user_id=user_id)

    if user.id == current_user.id or current_user.type_id == 1:
        if request.method == "GET":
            response = user.to_dict()
            response["documents"] = [document.to_dict() for document in user_documents]
            return response

        if request.method == "PUT":
            raw_data = request.get_json()

            if "id" in raw_data.keys():
                del raw_data["id"]

            if "type_id" in raw_data.keys():
                if current_user.type_id != 1:
                    return {"error": "Access denied"}, 403

            if "sex" in raw_data.keys():
                sex = request.get_json().get("sex")
                if sex and sex not in {"1", "2"}:
                    return {'error': "Invalid Gender"}, 422

            if "login" in raw_data.keys():
                if User.query.filter_by(login=raw_data["login"]).first():
                    return {"error": "User with this login already exists"}, 400

            if "password" in raw_data.keys():
                new_password = raw_data.pop("password")
                user.set_password(new_password)

            data = {key: raw_data[key] for key in set(raw_data.keys()) & set(get_fields_names(User))}
            for key, value in data.items():
                setattr(user, key, value)

            db.session.commit()
            return user.to_dict()

        if request.method == "DELETE":
            Document.query.filter_by(user_id=user_id).delete(synchronize_session="fetch")
            db.session.delete(user)
            db.session.commit()
            return {"info": "Successfully deleted"}, 204
    return {"error": "Access denied"}, 403


@app.route('/api/all_users/', methods=["GET"])
@login_required
def get_all_users():
    if current_user.type_id != 1:
        return {"error": "Access denied"}, 403

    users = User.query.all()
    response = [user.to_dict() for user in users]
    for user in response:
        user["documents"] = [document.to_dict() for document in
                             Document.query.filter_by(user_id=user["id"])]
    return response


@app.route('/api/new_document/', methods=["POST"])
@login_required
def create_document():
    raw_data = request.get_json()
    user_id = request.get_json().get('id')
    type_id = raw_data.get("type_id")
    data = raw_data.get("data")

    if not user_id:
        user_id = current_user.id

    if type_id and type_id not in {'1', '2', '3', '4'}:
        return {'error': 'Invalid Document Type'}, 422

    if user_id == current_user.id or current_user.type_id == 1:
        document = Document(user_id=user_id, type_id=type_id, data=data)
        db.session.add(document)
        db.session.commit()
        return document.to_dict()
    else:
        return {"error": "Access denied"}, 403


@app.route('/api/document/<document_id>/', methods=["GET", "PUT", "DELETE"])
@login_required
def get_or_change_document(document_id):
    document = Document.query.get_or_404(document_id)
    # user = User.query.filter_by(id=current_user.id).first()
    documen_owner = Document.query.filter_by(id=document_id).first()

    if documen_owner.user_id == current_user.id or current_user.type_id == 1:
        if request.method == "GET":
            response = document.to_dict()
            return response

        if request.method == "PUT":
            raw_data = request.get_json()

            if "id" in raw_data.keys():
                del raw_data["id"]

            if "type_id" in raw_data.keys():
                type_id = request.get_json().get("type_id")
                if type_id and type_id not in {'1', '2', '3', '4'}:
                    return {'error': 'Invalid Document Type'}, 422

            data = {key: raw_data[key] for key in set(raw_data.keys()) & set(get_fields_names(Document))}
            for key, value in data.items():
                setattr(document, key, value)

            db.session.commit()
            return document.to_dict()

        if request.method == "DELETE":
            db.session.delete(document)
            db.session.commit()
            return {"info": "Successfully deleted"}, 204
    return {"error": "Access denied"}, 403


@app.route('/api/procces_request/', methods=["POST"])
@login_required
def procces_request():
    for data_first_step in request.get_json():
        for data_second_step in data_first_step["Data"]:
            for data_third_step in data_second_step["Users"]:

                user_data = dict()

                credentials = data_third_step["Credentials"]
                user_data["login"] = credentials["username"]
                new_password = credentials["pass"]

                for key in set(data_third_step.keys()) & set(get_fields_names(User)):
                    user_data[key] = data_third_step[key]

                if User.query.filter_by(login=user_data["login"]).first():
                    return {"error":
                            "User with this login already exists"}, 400

                if "id" in user_data:
                    del user_data["id"]

                new_user = User(**user_data)
                new_user.set_password(new_password)

                db.session.add(new_user)
                db.session.commit()

                documents_data = data_third_step["Documents"]
                for document in documents_data:
                    document_type = document.pop("documentType_id")

                    new_document = Document(type_id=document_type,
                                            data=str(document),
                                            user_id=new_user.id)
                    db.session.add(new_document)
                    db.session.commit()

                user_data.clear()
    response = new_user.to_dict()
    response["documents"] = [document.to_dict() for document in
                             Document.query.filter_by(user_id=new_user.id)]
    return response
