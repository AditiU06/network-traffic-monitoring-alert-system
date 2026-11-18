"""Create a login.  Usage:  python create_user.py <username> <email> "<Role name>" [database file]
Roles: System Admin | Security Analyst | NetOps Admin.  The password is asked for (not shown)."""
import getpass, sys
from app.engines.e3_data_management import DataManagementService
from app.engines.e4_api_dashboard.security import hash_password

if len(sys.argv) < 4:
    sys.exit(__doc__)
username, email, role = sys.argv[1:4]
db = sys.argv[4] if len(sys.argv) > 4 else "network_monitor.db"
pw = getpass.getpass("Password (min 8 characters): ")
if len(pw) < 8:
    sys.exit("Password too short.")
uid = DataManagementService(db).create_user(role, username, email, hash_password(pw))
print(f"Created {username} ({role}), user id {uid}")
