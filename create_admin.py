from utils.auth import init_db, create_user
init_db()
create_user("admin", "a", email="thien3007@gmailcom", is_admin=True)
print("Admin created (username=admin). Change the password after first login.")