# main.py
ALLOWED_ORIGINS="https://aefunai.netlify.app"

import os
import uuid
import smtplib
import shutil
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
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy import (
    Column,
    Integer,
    String,
    Text,
    DateTime,
    LargeBinary,
    create_engine,
    ForeignKey,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from passlib.context import CryptContext
from jose import JWTError, jwt  # Use python-jose to match auth.py
from auth import (
    authenticate_admin,
    create_access_token as auth_create_token,
    decode_token as auth_decode_token,
    ADMIN_USERNAME,
)

import io
import logging

# Simple logger
logger = logging.getLogger("journal_app")
logging.basicConfig(level=logging.INFO)

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

# File size limit
MAX_FILE_SIZE_BYTES = 15 * 1024 * 1024  # 15 MB

# Add CORS middleware AFTER ALLOWED_ORIGINS is defined
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition", "Content-Length"],
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
    submissions = relationship("Submission", primaryjoin="User.id == Submission.submitted_by", back_populates="submitter")


class Submission(Base):
    __tablename__ = "submissions"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    authors = Column(String(255), nullable=False)
    abstract = Column(Text)
    file_path = Column(String(500), nullable=True)          # lightweight pointer or original name
    original_filename = Column(String(255))
    submitted_by = Column(Integer, ForeignKey("users.id"))
    submitted_at = Column(DateTime, default=datetime.utcnow)
    status = Column(String(50), default="pending")
    reviewed_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    file_blob = Column(LargeBinary, nullable=True)          # store uploaded file bytes here

    submitter = relationship("User", foreign_keys=[submitted_by], back_populates="submissions")


class Journal(Base):
    __tablename__ = "journals"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    authors = Column(String(255), nullable=False)
    abstract = Column(Text)
    file_path = Column(String(500), nullable=True)          # lightweight pointer
    original_filename = Column(String(255))
    uploaded_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    upload_date = Column(DateTime, default=datetime.utcnow)
    submission_id = Column(Integer, ForeignKey("submissions.id"), nullable=True)
    file_blob = Column(LargeBinary, nullable=True)          # store published file bytes here

    owner = relationship("User", back_populates="journals")


Base.metadata.create_all(bind=engine)

# Security utils
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_password_hash(password: str) -> str:
    # Bcrypt has a 72-byte limit; truncate if necessary
    password_bytes = password.encode('utf-8')
    if len(password_bytes) > 72:
        password_bytes = password_bytes[:72]
        password = password_bytes.decode('utf-8', errors='ignore')
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    # Bcrypt has a 72-byte limit; truncate if necessary for verification
    if not hashed_password:
        return False
    
    # Bcrypt has a 72 byte input limit; reject overly long passwords early
    try:
        if isinstance(plain_password, str) and len(plain_password.encode("utf-8")) > 72:
            # Truncate to 72 bytes for verification
            password_bytes = plain_password.encode("utf-8")[:72]
            plain_password = password_bytes.decode('utf-8', errors='ignore')
    except Exception:
        pass
    
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except (ValueError, AttributeError, TypeError) as e:
        logger.error(f"Password verification error: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected password verification error: {e}")
        return False


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
        logger.info(f"[EMAIL] Would send to {to_email}: {subject}")
        logger.info(f"[EMAIL] Attachment: {attachment_filename}")
        return True  # Return True for development
    
    try:
        msg = MIMEMultipart()
        msg['From'] = SMTP_USER
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        # Attach file
        if attachment_path and os.path.exists(attachment_path):
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
        logger.exception(f"Email sending failed: {e}")
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
    uploaded_by: Optional[int]  # allow None for env-admin
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
    """
    Decode a regular user token and return the DB user.
    Admin tokens (env-based) are rejected here to avoid admins being treated as normal users.
    """
    # If token is an env-based admin token, reject for user endpoints
    try:
        admin_payload = auth_decode_token(token)
        if admin_payload and admin_payload.get("admin") is True:
            raise HTTPException(status_code=401, detail="Admin token not allowed for user endpoints")
    except Exception:
        # auth_decode_token may raise for non-admin tokens — ignore those errors
        pass

    payload = decode_access_token(token)
    user_id = payload.get("sub")

    if user_id is None:
        raise HTTPException(status_code=401, detail="Invalid token payload")

    # Must be integer user id
    try:
        uid = int(user_id)
    except (ValueError, TypeError):
        raise HTTPException(status_code=401, detail="Invalid user id in token")

    user = db.query(User).filter(User.id == uid).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def require_admin(token: str = Depends(oauth2_scheme)):
    """Verify token belongs to the admin user defined in .env."""
    try:
        payload = auth_decode_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    if not payload.get("admin"):
        raise HTTPException(status_code=403, detail="Admin privileges required")

    username_in_token = payload.get("sub")
    if username_in_token != ADMIN_USERNAME:
        raise HTTPException(status_code=403, detail="Invalid admin token")

    class AdminUser:
        id = 0
        is_admin = True
        username = ADMIN_USERNAME
        full_name = "Admin"
        email = "admin@local"

    return AdminUser()


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
    
    # Create token with admin identifier (env-based admin)
    access_token = auth_create_token({"sub": ADMIN_USERNAME, "admin": True})
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me", response_model=UserOut)
def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user


# Routes: Submissions (for regular users)
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
    
    # Read file into bytes (chunked) up to MAX_FILE_SIZE_BYTES
    total = 0
    data = bytearray()
    try:
        while True:
            chunk = file.file.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_FILE_SIZE_BYTES:
                raise HTTPException(status_code=400, detail="File too large (max 15MB)")
            data.extend(chunk)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read uploaded file: {e}")
    finally:
        try:
            file.file.close()
        except Exception:
            pass

    # Save submission record (store bytes in DB)
    unique_name = f"{uuid.uuid4().hex}{os.path.splitext(file.filename)[1] or '.doc'}"
    submission = Submission(
        title=title,
        authors=authors,
        abstract=abstract,
        file_path=unique_name,            # lightweight pointer
        original_filename=file.filename,
        file_blob=bytes(data),
        submitted_by=current_user.id,
        status="pending",
    )
    db.add(submission)
    db.commit()
    db.refresh(submission)
    
    # Send email to review team
    temp_path = None
    try:
        if SMTP_USER and SMTP_PASSWORD:
            temp_path = os.path.join(SUBMISSIONS_DIR, unique_name)
            os.makedirs(SUBMISSIONS_DIR, exist_ok=True)
            with open(temp_path, "wb") as t:
                t.write(submission.file_blob)
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
            attachment_path=temp_path or "",
            attachment_filename=file.filename
        )
    finally:
        try:
            if temp_path and os.path.exists(temp_path):
                os.remove(temp_path)
        except Exception:
            pass
    
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
    submission = db.query(Submission).filter(Submission.id == submission_id).first()
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")

    if not submission.file_blob:
        raise HTTPException(status_code=404, detail="Submission file not found in database")

    filename = submission.original_filename or f"submission-{submission_id}.pdf"
    mime = "application/pdf" if filename.lower().endswith(".pdf") else "application/octet-stream"

    # Serve bytes from DB
    return StreamingResponse(
        io.BytesIO(submission.file_blob),
        media_type=mime,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(submission.file_blob))
        }
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
    
    # Read upload into bytes
    total = 0
    data = bytearray()
    try:
        while True:
            chunk = file.file.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_FILE_SIZE_BYTES:
                raise HTTPException(status_code=400, detail="File too large")
            data.extend(chunk)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read uploaded file: {e}")
    finally:
        try:
            file.file.close()
        except Exception:
            pass
    
    # Update submission status if linked
    if submission_id:
        submission = db.query(Submission).filter(Submission.id == submission_id).first()
        if submission:
            submission.status = "approved"
            if getattr(admin_user, "id", None) and admin_user.id != 0:
                submission.reviewed_by = admin_user.id
            submission.reviewed_at = datetime.utcnow()
    
    # Save journal record with bytes in DB
    uploaded_by_id = admin_user.id if getattr(admin_user, "id", None) and admin_user.id != 0 else None
    journal = Journal(
        title=title,
        authors=authors,
        abstract=abstract,
        file_path=f"{uuid.uuid4().hex}.pdf",
        original_filename=file.filename,
        file_blob=bytes(data),
        uploaded_by=uploaded_by_id,
        submission_id=submission_id,
    )
    db.add(journal)
    db.commit()
    db.refresh(journal)
    
    return journal


@app.post("/admin/submissions/{submission_id}/approve-publish", response_model=JournalOut)
def approve_and_publish_submission(
    submission_id: int,
    category: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    admin_user: User = Depends(require_admin),
):
    submission = db.query(Submission).filter(Submission.id == submission_id).first()
    if not submission:
        raise HTTPException(status_code=404, detail="Submission not found")

    if not submission.file_blob:
        raise HTTPException(status_code=404, detail="Submission file not found in database")

    # Mark submission approved
    submission.status = "approved"
    submission.reviewed_by = admin_user.id if getattr(admin_user, "id", None) and admin_user.id != 0 else None
    submission.reviewed_at = datetime.utcnow()

    # Create Journal record by copying bytes from submission
    journal = Journal(
        title=submission.title,
        authors=submission.authors,
        abstract=submission.abstract,
        file_path=f"{uuid.uuid4().hex}{os.path.splitext(submission.original_filename or '')[1] or '.pdf'}",
        original_filename=submission.original_filename,
        file_blob=submission.file_blob,   # copy bytes into journals table
        uploaded_by=admin_user.id if getattr(admin_user, "id", None) and admin_user.id != 0 else None,
        submission_id=submission.id,
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
    if not journal.file_blob:
        raise HTTPException(status_code=404, detail="File not found in database")
    filename = journal.original_filename or f"journal-{journal_id}.pdf"
    return StreamingResponse(
        io.BytesIO(journal.file_blob),
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Content-Length": str(len(journal.file_blob))
        }
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
    
    # Attempt to remove local file if it exists, then delete DB row
    try:
        try:
            if journal.file_path and os.path.exists(journal.file_path):
                os.remove(journal.file_path)
        except Exception:
            pass
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
