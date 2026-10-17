import os, sys, secrets, hashlib, hmac, sqlite3, shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, List
from fastapi import FastAPI, Depends, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.security import HTTPBasic
from fastapi.staticfiles import StaticFiles
from sqlalchemy import create_engine, Column, Integer, String, Boolean, ForeignKey, DateTime, Text, select, func
from sqlalchemy.orm import declarative_base, sessionmaker, Session, relationship
from pydantic import BaseModel, Field

DB_PATH = os.getenv("DATABASE_URL", "sqlite:///./best_view.db")
engine = create_engine(DB_PATH, connect_args={"check_same_thread": False} if DB_PATH.startswith("sqlite") else {})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()
SESSION_SECRET = os.getenv("SESSION_SECRET", "")
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "0") == "1"
SESSION_TTL_HOURS = int(os.getenv("SESSION_TTL_HOURS", "8"))

def utcnow(): return datetime.now(timezone.utc).replace(tzinfo=None)

class UserBranch(Base):
    __tablename__ = "user_branches"
    user_id = Column(Integer, ForeignKey("users.id"), primary_key=True)
    branch_id = Column(Integer, ForeignKey("branches.id"), primary_key=True)

class Branch(Base):
    __tablename__ = "branches"
    id = Column(Integer, primary_key=True)
    name = Column(String(120), unique=True, nullable=False)
    location = Column(String(200), nullable=False, default="")
    active = Column(Boolean, default=True, nullable=False)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False, index=True)
    full_name = Column(String(160), nullable=False)
    password_hash = Column(String(300), nullable=False)
    role = Column(String(30), nullable=False)
    active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    branches = relationship("Branch", secondary="user_branches")

class Customer(Base):
    __tablename__ = "customers"
    id = Column(Integer, primary_key=True)
    customer_code = Column(String(30), unique=True, nullable=False, index=True)
    full_name = Column(String(160), nullable=False)
    phone = Column(String(40), nullable=False)
    address = Column(String(250), default="")
    employer = Column(String(160), default="")
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    branch_id = Column(Integer, ForeignKey("branches.id"), nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    active = Column(Boolean, default=True, nullable=False)

class Loan(Base):
    __tablename__ = "loans"
    id = Column(Integer, primary_key=True)
    loan_code = Column(String(40), unique=True, nullable=False, index=True)
    customer_id = Column(Integer, ForeignKey("customers.id"), nullable=False)
    branch_id = Column(Integer, ForeignKey("branches.id"), nullable=False)
    officer_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    principal_ngwee = Column(Integer, nullable=False)
    interest_ngwee = Column(Integer, nullable=False, default=0)
    fee_ngwee = Column(Integer, nullable=False, default=0)
    total_due_ngwee = Column(Integer, nullable=False)
    due_date = Column(String(10), nullable=False)
    status = Column(String(20), nullable=False, default="active")
    created_at = Column(DateTime, default=utcnow, nullable=False)

class Payment(Base):
    __tablename__ = "payments"
    id = Column(Integer, primary_key=True)
    receipt_no = Column(String(50), unique=True, nullable=False, index=True)
    loan_id = Column(Integer, ForeignKey("loans.id"), nullable=False)
    amount_ngwee = Column(Integer, nullable=False)
    method = Column(String(30), nullable=False)
    reference = Column(String(100), default="")
    received_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    paid_at = Column(DateTime, default=utcnow, nullable=False)
    note = Column(String(250), default="")

class AuditEvent(Base):
    __tablename__ = "audit_events"
    id = Column(Integer, primary_key=True)
    actor_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(80), nullable=False)
    entity_type = Column(String(50), nullable=False)
    entity_id = Column(String(80), nullable=True)
    detail = Column(Text, default="")
    created_at = Column(DateTime, default=utcnow, nullable=False)

Base.metadata.create_all(engine)
app = FastAPI(title="Best View Money Lenders Ltd", version="0.1.0",
              description="Multi-branch loan tracking starter API. Secure deployment is required before real data.")
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent)), name="static")
ROLES = {"admin", "manager", "loan_officer", "cashier"}

def db_dep():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return "pbkdf2_sha256$310000$" + salt.hex() + "$" + dk.hex()

def verify_password(password: str, encoded: str) -> bool:
    try:
        _, rounds, salt_hex, expected = encoded.split("$")
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(rounds)).hex()
        return hmac.compare_digest(actual, expected)
    except Exception: return False

def sign_session(user_id: int, expires: int) -> str:
    payload = f"{user_id}:{expires}"
    sig = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return payload + ":" + sig

def current_user(request: Request, db: Session = Depends(db_dep)):
    if not SESSION_SECRET or len(SESSION_SECRET) < 32:
        raise HTTPException(503, "Server is not configured: set a strong SESSION_SECRET.")
    raw = request.cookies.get("bv_session", "")
    try:
        uid_s, exp_s, sig = raw.split(":")
        payload = f"{uid_s}:{exp_s}"
        expected = hmac.new(SESSION_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected) or int(exp_s) < int(datetime.now(timezone.utc).timestamp()):
            raise ValueError()
        user = db.get(User, int(uid_s))
        if not user or not user.active: raise ValueError()
        return user
    except Exception:
        raise HTTPException(401, "Login required")

def audit(db, actor, action, entity_type, entity_id=None, detail=""):
    db.add(AuditEvent(actor_id=actor.id if actor else None, action=action,
                      entity_type=entity_type, entity_id=str(entity_id) if entity_id is not None else None,
                      detail=detail[:2000]))
    db.commit()

def allowed_branch_ids(user: User):
    return [b.id for b in user.branches if b.active]

def require_role(*roles):
    def checker(user: User = Depends(current_user)):
        if user.role not in roles: raise HTTPException(403, "Insufficient permissions")
        return user
    return checker

def branch_ok(user, branch_id):
    if user.role == "admin": return True
    return branch_id in allowed_branch_ids(user)

def money(ngwee): return round((ngwee or 0)/100, 2)
def as_customer(c):
    return {"id":c.id,"customer_code":c.customer_code,"full_name":c.full_name,"phone":c.phone,
            "address":c.address,"employer":c.employer,"branch_id":c.branch_id,"created_at":c.created_at.isoformat()}
def loan_balance(db, loan):
    paid = db.scalar(select(func.coalesce(func.sum(Payment.amount_ngwee),0)).where(Payment.loan_id==loan.id)) or 0
    return max(0, loan.total_due_ngwee - paid), paid

class LoginIn(BaseModel):
    username: str
    password: str
class BranchIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    location: str = ""
class UserIn(BaseModel):
    username: str = Field(min_length=3, max_length=80)
    full_name: str
    password: str = Field(min_length=12, max_length=200)
    role: str
    branch_ids: List[int] = []
class CustomerIn(BaseModel):
    customer_code: str
    full_name: str
    phone: str
    address: str = ""
    employer: str = ""
    branch_id: int
class LoanIn(BaseModel):
    loan_code: str
    customer_id: int
    branch_id: int
    officer_id: Optional[int] = None
    principal_kwacha: float = Field(gt=0)
    interest_kwacha: float = Field(ge=0, default=0)
    fee_kwacha: float = Field(ge=0, default=0)
    due_date: str
class PaymentIn(BaseModel):
    amount_kwacha: float = Field(gt=0)
    method: str
    reference: str = ""
    note: str = ""

@app.get("/", response_class=HTMLResponse)
def home():
    return """<!doctype html><html><head><meta http-equiv="refresh" content="0;url=/app">
    <title>Best View Money Lenders</title></head><body><p>Opening <a href="/app">Best View Management System</a>…</p></body></html>"""

@app.get("/app", response_class=HTMLResponse)
def app_ui():
    return FileResponse(str(Path(__file__).with_name("index.html")))

@app.get("/manifest.webmanifest")
def pwa_manifest():
    return FileResponse(str(Path(__file__).with_name("manifest.webmanifest")), media_type="application/manifest+json")

@app.get("/service-worker.js")
def pwa_worker():
    return FileResponse(str(Path(__file__).with_name("service-worker.js")), media_type="application/javascript")

@app.post("/login")
def login(data: LoginIn, response: Response, db: Session = Depends(db_dep)):
    user = db.scalar(select(User).where(User.username == data.username))
    if not user or not user.active or not verify_password(data.password, user.password_hash):
        raise HTTPException(401, "Invalid username or password")
    if not SESSION_SECRET or len(SESSION_SECRET) < 32: raise HTTPException(503, "Server is not configured")
    exp = int(datetime.now(timezone.utc).timestamp()) + SESSION_TTL_HOURS*3600
    response.set_cookie("bv_session", sign_session(user.id, exp), httponly=True, secure=COOKIE_SECURE,
                        samesite="strict", max_age=SESSION_TTL_HOURS*3600, path="/")
    audit(db, user, "login", "user", user.id, "Successful login")
    return {"message":"Signed in","user":{"id":user.id,"username":user.username,"full_name":user.full_name,"role":user.role}}

@app.post("/logout")
def logout(response: Response, user: User = Depends(current_user), db: Session = Depends(db_dep)):
    audit(db,user,"logout","user",user.id,"User logged out")
    response.delete_cookie("bv_session", path="/")
    return {"message":"Signed out"}

@app.get("/me")
def me(user: User = Depends(current_user)):
    return {"id":user.id,"username":user.username,"full_name":user.full_name,"role":user.role,
            "branches":[{"id":b.id,"name":b.name} for b in user.branches]}

@app.get("/branches")
def list_branches(user: User = Depends(current_user), db: Session = Depends(db_dep)):
    q = select(Branch).where(Branch.active == True)
    if user.role != "admin": q = q.where(Branch.id.in_(allowed_branch_ids(user)))
    return [{"id":b.id,"name":b.name,"location":b.location} for b in db.scalars(q).all()]

@app.post("/branches")
def create_branch(data: BranchIn, user: User = Depends(require_role("admin")), db: Session = Depends(db_dep)):
    b = Branch(name=data.name.strip(), location=data.location.strip())
    db.add(b)
    try: db.commit(); db.refresh(b)
    except Exception: db.rollback(); raise HTTPException(409,"Branch name already exists")
    audit(db,user,"create","branch",b.id,b.name)
    return {"id":b.id,"name":b.name,"location":b.location}

@app.get("/users")
def list_users(user: User = Depends(require_role("admin")), db: Session = Depends(db_dep)):
    return [{"id":u.id,"username":u.username,"full_name":u.full_name,"role":u.role,"active":u.active,
             "branches":[{"id":b.id,"name":b.name} for b in u.branches]} for u in db.scalars(select(User)).all()]

@app.post("/users")
def create_user(data: UserIn, user: User = Depends(require_role("admin")), db: Session = Depends(db_dep)):
    if data.role not in ROLES: raise HTTPException(400,"Invalid role")
    if db.scalar(select(User).where(User.username==data.username)): raise HTTPException(409,"Username already exists")
    branches = [db.get(Branch,bid) for bid in data.branch_ids]
    if any(b is None or not b.active for b in branches): raise HTTPException(400,"Unknown or inactive branch")
    u = User(username=data.username.strip(),full_name=data.full_name.strip(),password_hash=hash_password(data.password),role=data.role,branches=branches)
    db.add(u); db.commit(); db.refresh(u)
    audit(db,user,"create","user",u.id,f"Created staff account role={u.role}")
    return {"id":u.id,"username":u.username,"full_name":u.full_name,"role":u.role,"branch_ids":data.branch_ids}

@app.post("/users/{user_id}/deactivate")
def deactivate_user(user_id: int, user: User = Depends(require_role("admin")), db: Session = Depends(db_dep)):
    target=db.get(User,user_id)
    if not target: raise HTTPException(404,"User not found")
    if target.id==user.id: raise HTTPException(400,"Use another admin to deactivate your own account")
    target.active=False; db.commit()
    audit(db,user,"deactivate","user",target.id,"Account deactivated")
    return {"message":"Account deactivated"}

@app.post("/customers")
def create_customer(data: CustomerIn, user: User = Depends(current_user), db: Session = Depends(db_dep)):
    if user.role not in {"admin","manager","loan_officer"}: raise HTTPException(403,"Role cannot create customers")
    if not branch_ok(user,data.branch_id): raise HTTPException(403,"Branch access denied")
    if not db.get(Branch,data.branch_id): raise HTTPException(400,"Unknown branch")
    c=Customer(customer_code=data.customer_code.strip(),full_name=data.full_name.strip(),phone=data.phone.strip(),
               address=data.address.strip(),employer=data.employer.strip(),created_by=user.id,branch_id=data.branch_id)
    db.add(c)
    try: db.commit(); db.refresh(c)
    except Exception: db.rollback(); raise HTTPException(409,"Customer code already exists")
    audit(db,user,"create","customer",c.id,f"Created customer code={c.customer_code}")
    return as_customer(c)

@app.get("/customers")
def list_customers(user: User = Depends(current_user), db: Session = Depends(db_dep)):
    q=select(Customer).where(Customer.active==True)
    if user.role!="admin": q=q.where(Customer.branch_id.in_(allowed_branch_ids(user)))
    return [as_customer(c) for c in db.scalars(q.order_by(Customer.id.desc())).all()]

@app.post("/loans")
def create_loan(data: LoanIn, user: User = Depends(current_user), db: Session = Depends(db_dep)):
    if user.role not in {"admin","manager","loan_officer"}: raise HTTPException(403,"Role cannot create loans")
    if not branch_ok(user,data.branch_id): raise HTTPException(403,"Branch access denied")
    customer=db.get(Customer,data.customer_id)
    if not customer or customer.branch_id != data.branch_id: raise HTTPException(400,"Customer must belong to selected branch")
    officer_id=data.officer_id or user.id
    officer=db.get(User,officer_id)
    if not officer or not officer.active: raise HTTPException(400,"Officer not found or inactive")
    if user.role=="loan_officer" and officer_id!=user.id: raise HTTPException(403,"Officers can only create loans assigned to themselves")
    if user.role!="admin" and data.branch_id not in allowed_branch_ids(officer): raise HTTPException(400,"Officer is not assigned to this branch")
    p=round(data.principal_kwacha*100); i=round(data.interest_kwacha*100); f=round(data.fee_kwacha*100)
    loan=Loan(loan_code=data.loan_code.strip(),customer_id=customer.id,branch_id=data.branch_id,officer_id=officer_id,
              principal_ngwee=p,interest_ngwee=i,fee_ngwee=f,total_due_ngwee=p+i+f,due_date=data.due_date,status="active")
    db.add(loan)
    try: db.commit(); db.refresh(loan)
    except Exception: db.rollback(); raise HTTPException(409,"Loan code already exists")
    audit(db,user,"create","loan",loan.id,f"Created loan code={loan.loan_code}; amount fields recorded")
    return {"id":loan.id,"loan_code":loan.loan_code,"customer_id":loan.customer_id,"branch_id":loan.branch_id,
            "officer_id":loan.officer_id,"principal_kwacha":money(p),"interest_kwacha":money(i),"fee_kwacha":money(f),
            "total_due_kwacha":money(loan.total_due_ngwee),"due_date":loan.due_date,"balance_kwacha":money(loan.total_due_ngwee)}

@app.get("/loans")
def list_loans(user: User = Depends(current_user), db: Session = Depends(db_dep)):
    q=select(Loan)
    if user.role!="admin": q=q.where(Loan.branch_id.in_(allowed_branch_ids(user)))
    if user.role=="loan_officer": q=q.where(Loan.officer_id==user.id)
    result=[]
    for l in db.scalars(q.order_by(Loan.id.desc())).all():
        balance,paid=loan_balance(db,l)
        result.append({"id":l.id,"loan_code":l.loan_code,"customer_id":l.customer_id,"branch_id":l.branch_id,
                       "officer_id":l.officer_id,"principal_kwacha":money(l.principal_ngwee),"total_due_kwacha":money(l.total_due_ngwee),
                       "paid_kwacha":money(paid),"balance_kwacha":money(balance),"due_date":l.due_date,
                       "status":"paid" if balance==0 else l.status})
    return result

@app.post("/loans/{loan_id}/payments")
def record_payment(loan_id: int, data: PaymentIn, user: User = Depends(current_user), db: Session = Depends(db_dep)):
    if user.role not in {"admin","manager","loan_officer","cashier"}: raise HTTPException(403,"Role cannot record payments")
    loan=db.get(Loan,loan_id)
    if not loan: raise HTTPException(404,"Loan not found")
    if not branch_ok(user,loan.branch_id): raise HTTPException(403,"Branch access denied")
    if user.role=="loan_officer" and loan.officer_id!=user.id: raise HTTPException(403,"Can only collect on your assigned loans")
    balance,_=loan_balance(db,loan)
    amount=round(data.amount_kwacha*100)
    if amount>balance: raise HTTPException(400,f"Payment exceeds remaining balance of K{money(balance):.2f}")
    receipt="BVM-"+datetime.now().strftime("%Y%m%d%H%M%S")+"-"+secrets.token_hex(3).upper()
    payment=Payment(receipt_no=receipt,loan_id=loan.id,amount_ngwee=amount,method=data.method.strip(),
                    reference=data.reference.strip(),received_by=user.id,note=data.note.strip())
    db.add(payment); db.commit(); db.refresh(payment)
    new_balance,_=loan_balance(db,loan)
    if new_balance==0: loan.status="paid"; db.commit()
    audit(db,user,"record_payment","payment",payment.id,f"receipt={receipt}; loan_id={loan.id}; amount_kwacha={money(amount):.2f}")
    return {"payment_id":payment.id,"receipt_no":receipt,"loan_code":loan.loan_code,"amount_kwacha":money(amount),
            "remaining_balance_kwacha":money(new_balance),"paid_at":payment.paid_at.isoformat(),"method":payment.method}

@app.get("/loans/{loan_id}/payments")
def list_payments(loan_id: int, user: User = Depends(current_user), db: Session = Depends(db_dep)):
    loan=db.get(Loan,loan_id)
    if not loan: raise HTTPException(404,"Loan not found")
    if not branch_ok(user,loan.branch_id): raise HTTPException(403,"Branch access denied")
    if user.role=="loan_officer" and loan.officer_id!=user.id: raise HTTPException(403,"Access denied")
    return [{"id":p.id,"receipt_no":p.receipt_no,"amount_kwacha":money(p.amount_ngwee),"method":p.method,
             "reference":p.reference,"received_by":p.received_by,"paid_at":p.paid_at.isoformat(),"note":p.note}
            for p in db.scalars(select(Payment).where(Payment.loan_id==loan_id).order_by(Payment.paid_at.desc())).all()]

@app.get("/dashboard")
def dashboard(user: User = Depends(current_user), db: Session = Depends(db_dep)):
    q=select(Loan)
    if user.role!="admin": q=q.where(Loan.branch_id.in_(allowed_branch_ids(user)))
    if user.role=="loan_officer": q=q.where(Loan.officer_id==user.id)
    loans=db.scalars(q).all()
    principal=sum(l.principal_ngwee for l in loans)
    outstanding=0; collected=0; overdue=0; active=0; paid_count=0
    today=datetime.now().date().isoformat()
    for l in loans:
        bal,pay=loan_balance(db,l); outstanding+=bal; collected+=pay
        if bal>0:
            active+=1
            if l.due_date < today: overdue+=bal
        else: paid_count+=1
    return {"loans_count":len(loans),"active_loans":active,"fully_paid_loans":paid_count,
            "principal_lent_kwacha":money(principal),"payments_collected_kwacha":money(collected),
            "outstanding_kwacha":money(outstanding),"overdue_balance_kwacha":money(overdue)}

@app.get("/audit")
def get_audit(limit: int=100, user: User=Depends(require_role("admin")), db: Session=Depends(db_dep)):
    limit=max(1,min(limit,500))
    q=select(AuditEvent).order_by(AuditEvent.created_at.desc()).limit(limit)
    events=db.scalars(q).all()
    return [{"id":e.id,"actor_id":e.actor_id,"action":e.action,"entity_type":e.entity_type,
             "entity_id":e.entity_id,"detail":e.detail,"created_at":e.created_at.isoformat()} for e in events]

@app.post("/admin/backup")
def backup(user: User=Depends(require_role("admin"))):
    if not DB_PATH.startswith("sqlite:///"): raise HTTPException(400,"This backup endpoint is for SQLite only; use managed database backups for PostgreSQL")
    source=Path(DB_PATH.replace("sqlite:///","",1))
    if not source.exists(): raise HTTPException(404,"Database file not found yet")
    backup_dir=Path("backups"); backup_dir.mkdir(exist_ok=True)
    target=backup_dir/f"best_view_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
    with sqlite3.connect(str(source)) as src, sqlite3.connect(str(target)) as dst:
        src.backup(dst)
    audit_db=SessionLocal()
    try: audit(audit_db,user,"backup","database",None,target.name)
    finally: audit_db.close()
    return {"message":"Local backup created. Move or replicate it to secure off-site storage.","file":str(target)}

def create_admin():
    db=SessionLocal()
    try:
        if db.scalar(select(User).where(User.role=="admin")):
            print("An admin already exists."); return
        username=input("Admin username: ").strip()
        full_name=input("Admin full name: ").strip()
        password=input("Admin password (minimum 12 characters): ")
        if len(password)<12: raise SystemExit("Password must be at least 12 characters.")
        admin=User(username=username,full_name=full_name,password_hash=hash_password(password),role="admin")
        db.add(admin); db.commit()
        print("Admin created. Sign in, then create branches and staff accounts.")
    finally: db.close()

if __name__ == "__main__":
    if len(sys.argv)>1 and sys.argv[1]=="create-admin": create_admin()
    else: print("Run with: uvicorn app:app --host 127.0.0.1 --port 8000")
