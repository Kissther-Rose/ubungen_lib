# Library Management System API

This RESTful API allows efficient management of a library system. Built using PHP, the Slim Framework, and JWT (JSON Web Token), it provides secure endpoints for managing users, authors, books, and their relationships. It streamlines library operations with modern technology.

## Features

- **User Management**: Register and authenticate users securely with JWT tokens.
- **Protected Endpoints**: Middleware ensures token verification and blacklist management for expired tokens.
- **CRUD Operations**:
  - Add and retrieve authors.
  - Add and retrieve books.
  - Manage relationships between books and authors.

## Technology Stack

- **PHP**: Backend development.
- **Slim Framework**: Lightweight framework for building RESTful APIs.
- **JWT (Firebase/JWT)**: Secure authentication handling.
- **MySQL**: Database for users, authors, and books.
- **SQLyog**: MySQL management tool.

## API Endpoints

### 1. User Endpoints

#### Register a User

**Method**: `POST`  
**Endpoint**: `/user/register`

**Request Body**:
```json
{
  "username": "yourUsername",
  "password": "yourPassword"
  
}
```

Response:

Success:
```json
{
  "status": "success",
  "token": null,
  "data": null
}

Failure:
```json
{
  "status": "fail",
  "data": {
    "title": "Username already exists!"
  }
}
Authenticate a User
Method: POST
Endpoint: /user/authenticate

Request Body:
```json
{
  "username": "yourUsername",
  "password": "yourPassword"
}
Response:

Success:
```json
{
  "status": "success",
  "token": "your_jwt_token",
  "data": null
}
Failure:
```json
{
  "status": "fail",
  "token": null,
  "data": {
    "title": "Authentication Failed!"
  }
}
2. Author Endpoints
Add a New Author
Method: POST
Endpoint: /authors/add

Request Body:
```json
{
  "name": "Author Name"
}
Response:
```json
{
  "status": "success",
  "token": "new_jwt_token",
  "data": null
}
Get List of Authors
Method: GET
Endpoint: /authors

Response:
```json
{
  "status": "success",
  "token": "new_jwt_token",
  "data": [
    {
      "author_id": 1,
      "name": "Author Name"
    },
    {
      "author_id": 2,
      "name": "Another Author"
    }
  ]
}
3. Book Endpoints
Add a New Book
Method: POST
Endpoint: /books/add

Request Body:
```json
{
  "title": "Book Title",
  "author_id": 1
}
Response:
```json
{
  "status": "success",
  "token": "new_jwt_token",
  "data": null
}
Get List of Books
Method: GET
Endpoint: /books

Response:
```json
{
  "status": "success",
  "token": "new_jwt_token",
  "data": [
    {
      "book_id": 1,
      "title": "Book Title",
      "author_id": 1
    },
    {
      "book_id": 2,
      "title": "Another Book",
      "author_id": 2
    }
  ]
}
4. Book-Author Relationship Endpoints
Add a Book-Author Relationship
Method: POST
Endpoint: /books/authors/add

Request Body:
```json
{
  "book_id": 1,
  "author_id": 1
}
Response:
```json
{
  "status": "success",
  "token": "new_jwt_token",
  "data": null
}
Get List of Book-Author Relationships
Method: GET
Endpoint: /books/authors

Response:
```json
{
  "status": "success",
  "token": "new_jwt_token",
  "data": [
    {
      "book_id": 1,
      "author_id": 1
    },
    {
      "book_id": 2,
      "author_id": 2
    }
  ]
}
```
5. Authorization
For protected endpoints, include the JWT token in the request headers:

Header:

How It Works
Endpoints: Each endpoint specifies the HTTP method and URL.
Request/Response: Detailed examples of payloads and expected responses.
Authentication: JWT tokens ensure secure access to protected routes.
This documentation ensures clarity for developers integrating with the Library Management System API.