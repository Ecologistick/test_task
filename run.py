from app import app, db
from app.models import DocumentType, GenderType, UserType


@app.shell_context_processor
def make_shell_context():
    return {'db': db,
            'DocumentType': DocumentType,
            "GenderType": GenderType,
            "UserType": UserType}
