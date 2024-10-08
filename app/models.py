from app import db, login_manager
from werkzeug.security import generate_password_hash,  check_password_hash
from flask_login import UserMixin
from sqlalchemy.orm import class_mapper
import sqlalchemy


def get_fields_names(cls):
    return [prop.key for prop in class_mapper(cls).iterate_properties
            if isinstance(prop, sqlalchemy.orm.ColumnProperty)]


@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(user_id)


class User(db.Model, UserMixin):

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    lastName = db.Column(db.String(255), nullable=True)
    firstName = db.Column(db.String(255), nullable=True)
    patrName = db.Column(db.String(255), nullable=True)
    sex = db.Column(db.Integer, db.ForeignKey("genders.id"), default=2)
    # birthDate = db.Column(db.Date)
    type_id = db.Column(db.Integer, db.ForeignKey("user_types.id"), default=2)

    login = db.Column(db.String(255), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self,  password):
        return check_password_hash(self.password_hash, password)

    def to_dict(self):
        data = {
            "id": self.id,
            "login": self.login,
            "lastName": self.lastName,
            "firstName": self.firstName,
            "patrName": self.patrName,
            "sex": str(GenderType.query.filter_by(id=self.sex).first()),
            "type": str(UserType.query.filter_by(id=self.type_id).first())
        }
        return data

    def __str__(self):
        return f"{self.lastName}, {self.login}"


class DocumentType(db.Model):

    __tablename__ = "document_types"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255), index=True, unique=True)

    def __str__(self):
        return f"{self.name}"


class Document(db.Model):

    __tablename__ = "documents"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    data = db.Column(db.String(9000), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    type_id = db.Column(db.Integer, db.ForeignKey("document_types.id"), default=1)

    def to_dict(self):
        data = {
            "id": self.id,
            "data": self.data,
            "user": str(User.query.filter_by(id=self.user_id).first()),
            "type": str(DocumentType.query.filter_by(id=self.type_id).first())
        }
        return data

    def __str__(self):
        return f"{self.id}, \
        {str(DocumentType.query.filter_by(id=self.type_id).first())}"


class UserType(db.Model):

    __tablename__ = "user_types"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255), index=True, unique=True)

    def __str__(self):
        return f"{self.name}"


class GenderType(db.Model):

    __tablename__ = "genders"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(255), index=True, unique=True)

    def __str__(self):
        return f"{self.name}"
