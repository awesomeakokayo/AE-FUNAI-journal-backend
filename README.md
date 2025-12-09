# AE-FUNAI Journal Platform Backend

A FastAPI-based backend for a Journal Publication and Reading Platform with user authentication, journal submission workflows, admin review, and public access.

## Overview

The Journal Platform Backend is a RESTful API that enables:
- **User Management**: Registration and authentication with JWT tokens
- **Journal Submissions**: Users submit journals for admin review
- **Admin Review & Publishing**: Admins approve submissions and publish to the public site
- **Public Access**: Unauthenticated users can search and download published journals
- **Email Notifications**: Submission notifications sent to review team
- **Database Storage**: Files stored as BLOBs in the database for reliability and portability

## Technology Stack

- **Framework**: FastAPI (Python 3.11+)
- **Database**: SQLAlchemy ORM with SQLite or PostgreSQL support
- **Authentication**: JWT (python-jose) + bcrypt password hashing
- **Email**: SMTP with attachment support
- **Server**: Uvicorn ASGI server

## Project Structure

```
journal backend/
├── main.py              # Core FastAPI application & routes
├── auth.py              # Authentication utilities (admin token generation)
├── requirements.txt     # Python dependencies
├── Dockerfile           # Docker container configuration
├── fly.toml            # Fly.io deployment config (if deployed)
├── .env                # Environment variables (not committed)
├── app.db              # SQLite database (local development)
├── uploads/            # Published journal files (backup/cache)
├── submissions/        # Temp storage for submission emails
└── README.md           # This file
```

## Features

### 1. User Authentication
- **Registration**: Create new user accounts with email validation
- **Login**: JWT-based authentication for regular users
- **Admin Login**: Separate login endpoint for environment-based admin users
- **Password Security**: Bcrypt hashing with 72-byte truncation for security

### 2. Journal Submission Workflow
- Users submit journals with title, authors, abstract, and PDF/DOC/DOCX file
- File size limit: 15 MB
- Submissions stored in database (`file_blob` column) for durability
- Review team notified via email with attachment
- Submission status: pending → approved/rejected

### 3. Admin Management
- View all submissions with filtering by status
- Download submission files
- Approve submissions and publish to public site
- Upload additional journals directly to the site
- Delete published journals
- Environment-based admin authentication (no database admin users)

### 4. Public Journal Access
- Search journals by title or author name
- List all published journals (paginated via query results)
- Download published journals as PDF
- Metadata visible without authentication

### 5. CORS & Cross-Origin Support
- Configurable allowed origins from `ALLOWED_ORIGINS` env var
- Credentials allowed for authenticated requests
- Supports both browser and API client requests

## API Endpoints

### Authentication

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | `/register` | Register new user | None |
| POST | `/login` | User login | None |
| POST | `/admin/login` | Admin login | None |
| GET | `/users/me` | Get current user info | User |

**Example: Register**
```bash
curl -X POST http://localhost:8000/register \
  -H "Content-Type: application/json" \
  -d '{"full_name":"John Doe","email":"john@example.com","password":"secure_pass"}'
```

**Example: Admin Login**
```bash
curl -X POST http://localhost:8000/admin/login \
  -F "username=username" \
  -F "password=**********"
```

### User Submissions

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | `/submissions/submit` | Submit journal for review | User |
| GET | `/submissions/my` | Get user's submissions | User |

**Example: Submit Journal**
```bash
curl -X POST http://localhost:8000/submissions/submit \
  -H "Authorization: Bearer <token>" \
  -F "title=My Research Paper" \
  -F "authors=John Doe, Jane Smith" \
  -F "abstract=Study on neural networks..." \
  -F "file=@paper.pdf"
```

### Admin Operations

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/admin/submissions` | List all submissions | Admin |
| GET | `/admin/submissions/{id}/download` | Download submission file | Admin |
| POST | `/admin/journals/upload` | Upload journal directly | Admin |
| POST | `/admin/submissions/{id}/approve-publish` | Approve & publish submission | Admin |
| DELETE | `/admin/journals/{id}` | Delete published journal | Admin |

**Example: List Submissions**
```bash
curl -X GET "http://localhost:8000/admin/submissions?status_filter=pending" \
  -H "Authorization: Bearer <admin_token>"
```

**Example: Approve & Publish**
```bash
curl -X POST http://localhost:8000/admin/submissions/1/approve-publish \
  -H "Authorization: Bearer <admin_token>" \
  -F "category=Research"
```

### Public Journals

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/journals` | List published journals | None |
| GET | `/journals/{id}` | Get journal details | None |
| GET | `/journals/{id}/download` | Download journal PDF | None |

**Example: Search Journals**
```bash
curl -X GET "http://localhost:8000/journals?q=neural+networks"
```

### Health & Status

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | API status message |
| GET | `/health` | Health check with timestamp |

## Database Schema

### Users Table
```sql
CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  full_name VARCHAR(200),
  email VARCHAR(200) UNIQUE,
  hashed_password VARCHAR(200),
  is_admin INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

### Submissions Table
```sql
CREATE TABLE submissions (
  id INTEGER PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  authors VARCHAR(255) NOT NULL,
  abstract TEXT,
  file_path VARCHAR(500),                  -- lightweight pointer
  original_filename VARCHAR(255),
  file_blob BLOB,                          -- full file bytes
  submitted_by INTEGER FOREIGN KEY,
  submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  status VARCHAR(50) DEFAULT 'pending',    -- pending, approved, rejected
  reviewed_by INTEGER FOREIGN KEY NULL,
  reviewed_at DATETIME NULL
);
```

### Journals Table
```sql
CREATE TABLE journals (
  id INTEGER PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  authors VARCHAR(255) NOT NULL,
  abstract TEXT,
  file_path VARCHAR(500),                  -- lightweight pointer
  original_filename VARCHAR(255),
  file_blob BLOB,                          -- full file bytes
  uploaded_by INTEGER FOREIGN KEY NULL,
  upload_date DATETIME DEFAULT CURRENT_TIMESTAMP,
  submission_id INTEGER FOREIGN KEY NULL
);
```

## Environment Variables

Create a `.env` file in the project root with the following:

```env
# Database (required)
DATABASE_URL=sqlite:///./app.db
# OR for PostgreSQL:
# DATABASE_URL=postgresql://user:password@localhost/journal_db

# Security (required)
SECRET_KEY=your-super-secret-key-change-this-in-production
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=1440

# Admin Authentication (required)
ADMIN_USERNAME=enterusername
ADMIN_PASSWORD=*******
ADMIN_PASSWORD_HASH=$2b$12$...  # bcrypt hash of password (optional, fallback to plaintext)

# CORS (optional, default: https://aefunai.netlify.app)
ALLOWED_ORIGINS=https://aefunai.netlify.app,https://localhost:3000

# Email (optional, but required for email notifications)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
REVIEW_EMAIL=review@funai.edu.ng

# Base URL for verification links (optional)
BASE_URL=https://your-domain.com
```

## Setup & Installation

### Local Development

1. **Clone the repository**
```bash
git clone https://github.com/awesomeakokayo/AE-FUNAI-journal-backend.git
cd "journal backend"
```

2. **Create a Python virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Set up environment variables**
```bash
cp .env.example .env
# Edit .env with your configuration
```

5. **Run the development server**
```bash
uvicorn main:app --reload
```

The API will be available at `http://localhost:8000`

### Docker Deployment

1. **Build the Docker image**
```bash
docker build -t journal-backend:latest .
```

2. **Run the container**
```bash
docker run -p 8080:8080 \
  -e DATABASE_URL="sqlite:///./app.db" \
  -e SECRET_KEY="your-secret-key" \
  -e ADMIN_USERNAME="funaijournalaccess" \
  -e ADMIN_PASSWORD="EstablishedIn25" \
  journal-backend:latest
```

### Fly.io Deployment

1. **Install flyctl**
```bash
curl -L https://fly.io/install.sh | sh
```

2. **Deploy**
```bash
flyctl deploy
```

3. **Set environment secrets**
```bash
flyctl secrets set SECRET_KEY=your-secret-key
flyctl secrets set ADMIN_PASSWORD=your-admin-password
flyctl secrets set DATABASE_URL=postgresql://...
```

## File Storage Strategy

### Database BLOB Storage
Files are stored directly in the database as `BLOB` columns:
- **Advantages**: No filesystem management, portable, backed up with database
- **Disadvantages**: Larger database size, slower for very large files (>100MB)

### Lightweight Pointer (file_path)
The `file_path` column stores a unique identifier (UUID) rather than full paths:
- Keeps database lightweight
- Optional disk cache for frequently accessed files
- Can be extended to cloud storage (S3, etc.)

### File Size Limits
- Submissions: 15 MB max (DOC, DOCX, PDF)
- Journals: 15 MB max (PDF only)

## Security Considerations

1. **Password Security**
   - Passwords hashed with bcrypt
   - 72-byte truncation for bcrypt compatibility
   - Plaintext fallback for admin password if bcrypt unavailable

2. **JWT Tokens**
   - Access token expiry: 1440 minutes (configurable)
   - Tokens signed with SECRET_KEY
   - Admin tokens separate from user tokens

3. **CORS**
   - Specific origin whitelist required (no wildcard with credentials)
   - Credentials allowed only for trusted origins

4. **Admin Separation**
   - Admin users defined in `.env` (not database)
   - Admin tokens use different format (`"admin": true`)
   - Admin endpoints reject user tokens

5. **Email Security**
   - SMTP over TLS
   - Password stored in environment variables only
   - Graceful degradation if email config missing

## Error Handling

All endpoints return standard HTTP status codes:
- `200 OK` - Successful request
- `201 Created` - Resource created
- `400 Bad Request` - Invalid input
- `401 Unauthorized` - Missing/invalid authentication
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `500 Internal Server Error` - Server error

Error responses include a detail message:
```json
{
  "detail": "Email already registered"
}
```

## Logging

The application logs to stdout with the following levels:
- `INFO`: General application events (emails sent, submissions received)
- `ERROR`: Exceptions and failures
- `DEBUG`: (when logging level set to DEBUG)

Monitor logs with:
```bash
# Local
# stdout will show logs

# Docker
docker logs <container_id>

# Fly.io
flyctl logs
```

## Common Issues & Troubleshooting

### bcrypt Backend Not Available
**Error**: `AttributeError: module 'bcrypt' has no attribute '__about__'`

**Solution**: 
- Ensure Docker image has build tools: `build-essential`, `python3-dev`, `libffi-dev`, `libssl-dev`
- Fallback: Admin login uses plaintext `ADMIN_PASSWORD` env var if bcrypt fails

### CORS Errors
**Error**: `No 'Access-Control-Allow-Origin' header`

**Solution**:
- Set `ALLOWED_ORIGINS` env var to match your frontend domain
- Cannot use wildcard `*` with credentials=true

### Email Not Sending
**Error**: Email sent but not received

**Solutions**:
- Verify SMTP credentials and settings
- Check spam/junk folder
- Ensure `REVIEW_EMAIL` is valid
- For Gmail, use app-specific password (not account password)

### File Not Found on Download
**Error**: `404 File not found in database`

**Solution**:
- Files are stored in DB as `file_blob`
- Ensure file was successfully uploaded
- Check database connectivity

## API Response Examples

### Submit Journal (Success)
```json
{
  "id": 1,
  "message": "Journal submitted successfully. It has been sent for review.",
  "status": "pending"
}
```

### Get Journal Details
```json
{
  "id": 1,
  "title": "Neural Networks in Medicine",
  "authors": "John Doe, Jane Smith",
  "abstract": "A comprehensive study...",
  "original_filename": "paper.pdf",
  "upload_date": "2025-12-01T10:30:00",
  "uploaded_by": null
}
```

### Admin Submissions List
```json
[
  {
    "id": 1,
    "title": "Research Paper",
    "authors": "Author Name",
    "abstract": "Abstract text...",
    "original_filename": "paper.pdf",
    "submitted_at": "2025-11-28T15:00:00",
    "submitted_by": 2,
    "status": "pending",
    "submitter_name": "John Doe",
    "submitter_email": "john@example.com"
  }
]
```

## Performance Optimization Tips

1. **Database Indexes**: Consider indexing on frequently queried columns (email, status, submitted_at)
2. **Pagination**: Implement limit/offset for large result sets
3. **Caching**: Cache journal listings and metadata (Redis optional)
4. **File Compression**: Pre-compress PDFs before upload for reduced DB size
5. **Async Email**: Email sending is synchronous; consider Celery for large volumes

## Future Enhancements

- [ ] User email verification workflow
- [ ] Advanced search with filters (date range, category, author)
- [ ] Submission revision/resubmission workflow
- [ ] Role-based access control (reviewers, editors)
- [ ] S3/Cloud storage integration
- [ ] Rate limiting and API quotas
- [ ] Analytics dashboard
- [ ] Multi-language support
- [ ] API versioning

## Contributing

To contribute:
1. Create a feature branch (`git checkout -b feature/your-feature`)
2. Commit changes (`git commit -am 'Add your feature'`)
3. Push to the branch (`git push origin feature/your-feature`)
4. Open a Pull Request

## License

This project is proprietary software for AE-FUNAI. All rights reserved.

## Support

For issues or questions:
- Open an issue on GitHub
- Contact: awesomeakokayo@gmail.com
- Documentation: See API endpoints section above

---

**Last Updated**: December 1, 2025  
**Version**: 1.0.0  
**Python**: 3.11+  
**FastAPI**: 0.104.0+
