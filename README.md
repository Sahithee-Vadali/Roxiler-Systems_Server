# Store Ratings Backend

A Node.js backend API for a store rating system with user authentication and role-based access control.

## Features

- User authentication (signup/login) with JWT
- Role-based access (USER and OWNER roles)
- Store management (create stores as owner)
- Store rating system (users can rate stores)
- PostgreSQL database with Prisma ORM

## Setup Instructions

### 1. Install Dependencies
```bash
npm install
```

### 2. Environment Variables
Create a `.env` file in the server directory with:
```
DATABASE_URL="your-neon-connection-string-here"
JWT_SECRET="your-super-secret-jwt-key-change-this-in-production"
PORT=5000
```

### 3. Database Setup
```bash
# Generate Prisma client
npm run db:generate

# Push schema to database
npm run db:push
```

### 4. Start the Server
```bash
# Development mode
npm run dev

# Production mode
npm start
```

## API Endpoints

### Authentication
- `POST /signup` - Register a new user
- `POST /login` - Login user

### Stores
- `POST /stores` - Create a new store (OWNER only)
- `GET /stores` - Get all stores with average ratings
- `POST /stores/:id/rate` - Rate a store (USER only)

## Usage Examples

### Signup
```bash
curl -X POST http://localhost:5000/signup \
  -H "Content-Type: application/json" \
  -d '{"name":"John Doe","email":"john@example.com","password":"password123","role":"USER"}'
```

### Login
```bash
curl -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"email":"john@example.com","password":"password123"}'
```

### Create Store (requires OWNER token)
```bash
curl -X POST http://localhost:5000/stores \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{"name":"My Store","address":"123 Main St"}'
```

### Rate Store (requires USER token)
```bash
curl -X POST http://localhost:5000/stores/1/rate \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -d '{"rating":5}'
```

