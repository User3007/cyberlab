from .db import SessionLocal, engine
from .models import User
from passlib.hash import bcrypt
from sqlalchemy.exc import IntegrityError

# Create tables if not exist
def init_db():
    User.metadata = User.__table__.metadata
    from .db import Base
    Base.metadata.create_all(bind=engine)

def create_user(username: str, password: str, email: str = None, is_admin: bool = False):
    session = SessionLocal()
    try:
        pw_hash = bcrypt.hash(password)
        user = User(username=username, email=email, password_hash=pw_hash, is_admin=is_admin)
        session.add(user)
        session.commit()
        session.refresh(user)
        return user
    except IntegrityError:
        session.rollback()
        return None
    finally:
        session.close()

def authenticate_user(username: str, password: str):
    session = SessionLocal()
    try:
        user = session.query(User).filter(User.username == username).first()
        if user and bcrypt.verify(password, user.password_hash):
            return user
        return None
    finally:
        session.close()

def get_user_by_username(username: str):
    session = SessionLocal()
    try:
        return session.query(User).filter(User.username == username).first()
    finally:
        session.close()

def list_users():
    session = SessionLocal()
    try:
        return session.query(User).order_by(User.id).all()
    finally:
        session.close()

def change_password(username: str, new_password: str):
    session = SessionLocal()
    try:
        user = session.query(User).filter(User.username == username).first()
        if not user:
            return False
        user.password_hash = bcrypt.hash(new_password)
        session.commit()
        return True
    finally:
        session.close()