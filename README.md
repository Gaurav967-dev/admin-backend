# Admin System Backend

REST API developed with Python, FastAPI, SQLAlchemy, and PostgreSQL.

# Features

- Sign In and Sign Up
- Argon2 Password Hashing
- JWT Authentication
- ID Token, Access Token, Refresh Token
- Token Verification
- Refresh Token Rotation
- Logout
- User CRUD
- Employee Profile APIs

## Installation

1. Clone the backend repository.
2. Open the folder in VS Code.
3. Create a virtual environment: py -m venv venv
4. Activate it: .\venv\Scripts\Activate.ps1
5. Install dependencies: pip install -r requirements.txt
6. Create PostgreSQL database: CREATE DATABASE admin_management;
7. Create `.env` and configure:
   DATABASE_URL=postgresql+psycopg://postgres:YOUR_PASSWORD@localhost:5432/admin_management
   JWT_SECRET_KEY=YOUR_RANDOM_SECRET
   FRONTEND_ORIGIN=http://localhost:3000
   COOKIE_SECURE=false
8. Start the API: uvicorn app.main:app --reload

# API Documentation

http://localhost:8000/docs

# API Endpoints

POST /sign,
POST /signup,
GET /verify-token,
POST /refresh-token,
POST /logout,

GET /dashboard,

GET /user,
POST /user,
PUT /user,
DELETE /user,

GET /profile,
PUT /profile,
PATCH /profile,