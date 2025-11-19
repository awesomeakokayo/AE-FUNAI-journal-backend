ALLOWED_ORIGINS="https://aefunai.netlify.app"

import os
import uuid
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    status,
    UploadFile,
    File,
    Form,
    Request,
)
import re
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    DateTime,
    create_engine,
    ForeignKey,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from passlib.context import CryptContext
from jose import JWTError, jwt  # Use python-jose to match auth.py
from auth import authenticate_admin, create_access_token as auth_create_token, decode_token as auth_decode_token

# FastAPI app
app = FastAPI(title="Journal Platform API")

# Configuration 
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
SUBMISSIONS_DIR = os.path.join(BASE_DIR, "submissions")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(SUBMISSIONS_DIR, exist_ok=True)

DATABASE_URL = os.environ.get("DATABASE_URL")
SECRET_KEY = os.environ.get("SECRET_KEY")
ALGORITHM = os.environ.get("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

ALLOWED_ORIGINS_ENV = os.environ.get("ALLOWED_ORIGINS", "https://aefunai.netlify.app")
ALLOWED_ORIGINS = [o.strip() for o in ALLOWED_ORIGINS_ENV.split(",") if o.strip()]

# Add CORS middleware AFTER ALLOWED_ORIGINS is defined
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Email configuration (set via environment variables)
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
REVIEW_EMAIL = os.environ.get("REVIEW_EMAIL", "awesomeakokayo@gmail.com")

# Database setup 
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable is required")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY environment variable is required")

# Handle both SQLite and PostgreSQL
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
else:
    # PostgreSQL or other databases
    engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    full_name = Column(String(200))
    email = Column(String(200), unique=True, index=True, nullable=False)
    hashed_password = Column(String(200), nullable=False)
    is_admin = Column(Integer, default=0)  # 0 or 1
    created_at = Column(DateTime, default=datetime.utcnow)

    journals = relationship("Journal", back_populates="owner")
    submissions = relationship("Submission", back_populates="submitter")


class Submission(Base):
    __tablename__ = "submissions"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    authors = Column(String(255), nullable=False)
    abstract = Column(Text)
    file_path = Column(String(500), nullable=False)
    original_filename = Column(String(255))
    submitted_by = Column(Integer, ForeignKey("users.id"))
    submitted_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String(50), default="pending")
    reviewed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    
    submitter = relationship("User", foreign_keys=[submitted_by], back_populates="submissions")


class Journal(Base):
    __tablename__ = "journals"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    authors = Column(String(255), nullable=False)
    abstract = Column(Text)
    file_path = Column(String(500), nullable=False)
    original_filename = Column(String(255))
    uploaded_by = Column(Integer, ForeignKey("users.id"))
    upload_date = Column(DateTime, default=datetime.utcnow)
    submission_id = Column(Integer, ForeignKey("submissions.id"), nullable=True)

    owner = relationship("User", back_populates="journals")


Base.metadata.create_all(bind=engine)

# Security utils
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> dict:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def send_email_with_attachment(
    to_email: str,
    subject: str,
    body: str,
    attachment_path: str,
    attachment_filename: str
) -> bool:
    """Send email with attachment. Returns True if successful."""
    if not SMTP_USER or not SMTP_PASSWORD:
        # In development, just log instead of sending
        print(f"[EMAIL] Would send to {to_email}: {subject}")
        print(f"[EMAIL] Attachment: {attachment_filename}")
        return True  # Return True for development
    
    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_USER
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        # Attach file
        with open(attachment_path, "rb") as attachment:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment.read())
        
        encoders.encode_base64(part)
        part.add_header(
            'Content-Disposition',
            f'attachment; filename= {attachment_filename}'
        )
        msg.attach(part)
        
        # Send email
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Email sending failed: {e}")
        return False


# Pydantic Schemas
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserCreate(BaseModel):
    full_name: str
    email: EmailStr
    password: str


class UserOut(BaseModel):
    id: int
    full_name: str
    email: EmailStr
    is_admin: int

    class Config:
        orm_mode = True


class SubmissionOut(BaseModel):
    id: int
    title: str
    authors: str
    abstract: Optional[str]
    original_filename: Optional[str]
    submitted_at: datetime
    submitted_by: int
    status: str
    submitter_name: Optional[str] = None
    submitter_email: Optional[str] = None

    class Config:
        orm_mode = True


class JournalOut(BaseModel):
    id: int
    title: str
    authors: str
    abstract: Optional[str]
    original_filename: Optional[str]
    upload_date: datetime
    uploaded_by: int

    class Config:
        orm_mode = True


@app.middleware("http")
async def normalize_path_middleware(request: Request, call_next):
    path = request.scope.get("path", "")
    # Replace multiple slashes with a single slash, but keep the leading slash
    normalized = re.sub(r"/{2,}", "/", path)
    if normalized != path:
        request.scope["path"] = normalized
        request.scope["raw_path"] = normalized.encode("utf-8")
    return await call_next(request)


# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Auth dependency
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    payload = decode_access_token(token)
    user_id = payload.get("sub")
    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def require_admin(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """Dependency to require admin access. Handles both database admin users and auth.py admin."""
    try:
        # First try to decode with auth.py (for admin tokens)
        payload = auth_decode_token(token)
        if payload and payload.get("admin") is True:
            # Return a mock admin user object for auth.py admin
            class AdminUser:
                id = 0
                is_admin = 1
                full_name = "Admin"
                email = "admin@admin"
            return AdminUser()
        
        # Otherwise, try to decode with main.py's jwt (for database users)
        payload = decode_access_token(token)
        user_id = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        user = db.query(User).filter(User.id == int(user_id)).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        if not user.is_admin:
            raise HTTPException(status_code=403, detail="Admin access required")
        return user
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


# Routes: Auth
@app.post("/register", response_model=UserOut)
def register(user_in: UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == user_in.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(
        full_name=user_in.full_name,
        email=user_in.email,
        hashed_password=get_password_hash(user_in.password),
        is_admin=0,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    access_token = create_access_token({"sub": str(user.id)})
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/admin/login", response_model=Token)
def admin_login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Admin login using credentials from auth.py"""
    if not authenticate_admin(form_data.username, form_data.password):
        raise HTTPException(status_code=401, detail="Incorrect admin username or password")
    
    # Create token with admin identifier
    # We'll use a special format to identify admin tokens
    access_token = auth_create_token({"sub": "admin", "admin": True})
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me", response_model=UserOut)
def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user


# Routes: Submissions (for regular users)
MAX_FILE_SIZE_BYTES = 15 * 1024 * 1024
ALLOWED_SUBMISSION_TYPES = [
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/pdf"
]  # DOC, DOCX, PDF


@app.post("/submissions/submit")
def submit_journal(
    title: str = Form(...),
    authors: str = Form(...),
    abstract: Optional[str] = Form(None),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Submit a journal for review. Sends email to review team."""
    # Validate file type
    if file.content_type not in ALLOWED_SUBMISSION_TYPES:
        raise HTTPException(
            status_code=400,
            detail="Only DOC, DOCX, or PDF files are allowed for submission"
        )
    
    # Save submission file
    file_ext = os.path.splitext(file.filename)[1] or ".doc"
    unique_name = f"{uuid.uuid4().hex}{file_ext}"
    dest_path = os.path.join(SUBMISSIONS_DIR, unique_name)
    
    total = 0
    with open(dest_path, "wb") as buffer:
        for chunk in iter(lambda: file.file.read(1024 * 1024), b""):
            total += len(chunk)
            if total > MAX_FILE_SIZE_BYTES:
                buffer.close()
                os.remove(dest_path)
                raise HTTPException(status_code=400, detail="File too large (max 15MB)")
            buffer.write(chunk)
    
    # Save submission record
    submission = Submission(
        title=title,
        authors=authors,
        abstract=abstract,
        file_path=dest_path,
        original_filename=file.filename,
        submitted_by=current_user.id,
        status="pending",
    )
    db.add(submission)
    db.commit()
    db.refresh(submission)
    
    # Send email to review team
    email_body = f"""
New Journal Submission Received

Title: {title}
Authors: {authors}
Submitted by: {current_user.full_name} ({current_user.email})
Submitted at: {submission.submitted_at.strftime('%Y-%m-%d %H:%M:%S')}

Abstract:
{abstract or 'No abstract provided'}

Please review this submission and upload it to the site if approved.
Submission ID: {submission.id}
"""
    
    send_email_with_attachment(
        to_email=REVIEW_EMAIL,
        subject=f"New Journal Submission: {title}",
        body=email_body,
        attachment_path=dest_path,
        attachment_filename=file.filename
    )
    
    return {
        "id": submission.id,
        "message": "Journal submitted successfully. It has been sent for review.",
        "status": "pending"
    }


@app.get("/submissions/my", response_model=List[SubmissionOut])
def my_submissions(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get current user's submissions."""
    submissions = db.query(Submission).filter(
        Submission.submitted_by == current_user.id
    ).order_by(Submission.submitted_at.desc()).all()
    
    result = []
    for sub in submissions:
        sub_dict = {
            "id": sub.id,
            "title": sub.title,
            "authors": sub.authors,
            "abstract": sub.abstract,
            "original_filename": sub.original_filename,
            "submitted_at": sub.submitted_at,
            "submitted_by": sub.submitted_by,
            "status": sub.status,
            "submitter_name": current_user.full_name,
            "submitter_email": current_user.email,
        }
        result.append(sub_dict)
    
    return result


# Routes: Admin - Submissions Management
@app.get("/admin/submissions", response_model=List[SubmissionOut])
def list_submissions(
    status_filter: Optional[str] = None,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_admin),
):
    """List all submissions (admin only)."""
    query = db.query(Submission)
    if status_filter:
        query = query.filter(Submission.status == status_filter)
    
    submissions = query.order_by(Submission.submitted_at.desc()).all()
    
    result = []
    for sub in submissions:
        submitter = db.query(User).filter(User.id == sub.submitted_by).first()
        sub_dict = {
            "id": sub.id,
            "title": sub.title,
            "authors": sub.authors,
            "abstract": sub.abstract,
            "original_filename": sub.original_filename,
            "submitted_at": sub.submitted_at,
            "submitted_by": sub.submitted_by,
            "status": sub.status,
            "submitter_name": submitter.full_name if submitter else None,
            "submitter_email": submitter.email if submitter else None,
        }
        result.append(sub_dict)
    
    return result


@app.get("/admin/submissions/{submission_id}/download")
def download_submission(
    submission_id: int,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_admin),
):
    """Download a submission file (admin only)."""
    submission = db.query(Submission).filter(Submission.id == submission_id).first()
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")
    
    if not os.path.exists(submission.file_path):
        raise HTTPException(status_code=404, detail="File not found")
    
    return FileResponse(
        path=submission.file_path,
        filename=submission.original_filename,
        media_type="application/octet-stream"
    )


# Routes: Admin - Journal Upload (Admin Only)
ALLOWED_JOURNAL_TYPES = ["application/pdf"]  # Only PDF for published journals


@app.post("/admin/journals/upload", response_model=JournalOut)
def admin_upload_journal(
    title: str = Form(...),
    authors: str = Form(...),
    abstract: Optional[str] = Form(None),
    file: UploadFile = File(...),
    submission_id: Optional[int] = Form(None),
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_admin),
):
    """Upload a journal to the public site (admin only)."""
    # Validate file type
    if file.content_type not in ALLOWED_JOURNAL_TYPES:
        raise HTTPException(status_code=400, detail="Only PDF files are allowed for published journals")
    
    # Save file
    unique_name = f"{uuid.uuid4().hex}.pdf"
    dest_path = os.path.join(UPLOAD_DIR, unique_name)
    
    total = 0
    with open(dest_path, "wb") as buffer:
        for chunk in iter(lambda: file.file.read(1024 * 1024), b""):
            total += len(chunk)
            if total > MAX_FILE_SIZE_BYTES:
                buffer.close()
                os.remove(dest_path)
                raise HTTPException(status_code=400, detail="File too large")
            buffer.write(chunk)
    
    # Update submission status if linked
    if submission_id:
        submission = db.query(Submission).filter(Submission.id == submission_id).first()
        if submission:
            submission.status = "approved"
            submission.reviewed_by = admin_user.id
            submission.reviewed_at = datetime.utcnow()
    
    # Save journal record
    journal = Journal(
        title=title,
        authors=authors,
        abstract=abstract,
        file_path=dest_path,
        original_filename=file.filename,
        uploaded_by=admin_user.id,
        submission_id=submission_id,
    )
    db.add(journal)
    db.commit()
    db.refresh(journal)
    
    return journal


# Routes: Public Journals
@app.get("/journals", response_model=List[JournalOut])
def list_journals(q: Optional[str] = None, db: Session = Depends(get_db)):
    """List all published journals (public)."""
    query = db.query(Journal)
    if q:
        q_term = f"%{q}%"
        query = query.filter((Journal.title.ilike(q_term)) | (Journal.authors.ilike(q_term)))
    journals = query.order_by(Journal.upload_date.desc()).all()
    return journals


@app.get("/journals/{journal_id}", response_model=JournalOut)
def get_journal(journal_id: int, db: Session = Depends(get_db)):
    """Get journal details (public)."""
    journal = db.query(Journal).filter(Journal.id == journal_id).first()
    if not journal:
        raise HTTPException(status_code=404, detail="Journal not found")
    return journal


@app.get("/journals/{journal_id}/download")
def download_journal(journal_id: int, db: Session = Depends(get_db)):
    """Download journal PDF (public)."""
    journal = db.query(Journal).filter(Journal.id == journal_id).first()
    if not journal:
        raise HTTPException(status_code=404, detail="Journal not found")
    if not os.path.exists(journal.file_path):
        raise HTTPException(status_code=404, detail="File not found on server")
    return FileResponse(
        path=journal.file_path,
        filename=journal.original_filename,
        media_type="application/pdf"
    )


@app.delete("/admin/journals/{journal_id}")
def delete_journal(
    journal_id: int,
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_admin),
):
    """Delete a journal (admin only)."""
    journal = db.query(Journal).filter(Journal.id == journal_id).first()
    if not journal:
        raise HTTPException(status_code=404, detail="Journal not found")
    
    # Delete file
    try:
        if os.path.exists(journal.file_path):
            os.remove(journal.file_path)
    except Exception:
        pass
    
    db.delete(journal)
    db.commit()
    return {"detail": "Journal deleted"}


@app.get("/")
def root():
    return {"status": "ok", "message": "Journal Platform API"}


# Health check
@app.get("/health")
def health():
    return {"status": "ok", "timestamp": datetime.utcnow().isoformat()}
    return {"status": "ok"}
