# Best View Money Lenders Ltd — Management System Starter

This is a runnable **starter web application** for a multi-branch lender with up to 25 loan officers. It includes individual logins, role-based permissions, branch-scoped access, customers, loans, payment records, audit events, and database backup commands.

## Important before real customer data
This is a starter implementation, not a hosted/live production service and not a substitute for a professional security review. Do not enter real NRC numbers or customer financial data until it has been deployed over HTTPS, configured with strong secrets, tested, and backed up to a separate secure location. It is intentionally designed to be extended.

## Included roles
- `admin`: manages branches and users; can see all branches and reports.
- `manager`: can access assigned branch(es), customers, loans, and payments.
- `loan_officer`: can create/view customers and loans within assigned branch(es), and record payments on loans they are assigned to.
- `cashier`: can view loans and record payments within assigned branch(es); cannot manage staff.

The app applies branch scoping to normal data endpoints. Admins can view across branches. The first admin is created using a one-time setup command.

## Run locally
Requires Python 3.11+.

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate
pip install -r requirements.txt
export SESSION_SECRET="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
python app.py create-admin
uvicorn app:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/app` for the mobile-friendly management interface, or `/docs` to inspect the API. The `/login` endpoint returns a signed session cookie. For local testing, use a client that stores cookies (e.g. browser or curl with `-c cookies.txt -b cookies.txt`).

### First setup
1. Create the admin with `python app.py create-admin`.
2. Sign in using `POST /login` with JSON `{"username":"...","password":"..."}`.
3. Create branches using `POST /branches`.
4. Create staff using `POST /users`, assigning a role and branch IDs.
5. Register customers, create loans, and record payments.

## User interface\nThe responsive, installable PWA interface at `/app` can be added to an Android home screen from the browser menu after HTTPS deployment. It caches only the app shell, never API/customer/loan data. It includes dashboard, customers, loans and balances, payment recording, branch management, staff accounts, and audit history. It calls the API using the signed session cookie.\n\n## Core endpoints
- `POST /login`, `POST /logout`, `GET /me`
- `GET/POST /branches`
- `GET/POST /users` (admin only)
- `GET/POST /customers`
- `GET/POST /loans`
- `GET/POST /loans/{loan_id}/payments`
- `GET /dashboard`
- `GET /audit` (admin only)
- `POST /admin/backup` (admin only; creates a local SQLite backup file)

All amounts are stored as integer ngwee (100 ngwee = K1) to avoid floating-point money errors. Loan repayment totals are calculated from principal + fixed interest + any fee entered at origination. Configure your legally approved pricing and disclosures before using real loans.

## Security and operations checklist before launch
- Deploy behind HTTPS and set `COOKIE_SECURE=1`.
- Set a long, unique `SESSION_SECRET`; keep it in a secret manager/environment, never in source control.
- Use managed PostgreSQL instead of SQLite for a multi-user production deployment.
- Store encrypted backups off the server, restrict who can restore them, and test restores.
- Add MFA, rate limiting, account lockout, password reset, session revocation, CSRF protections, monitoring, and security testing.
- Use minimal customer data; define retention and access rules. Never store passwords in plain text.
- Review applicable Zambian lending, consumer-protection, privacy, record-keeping, and licensing requirements with a qualified professional.
