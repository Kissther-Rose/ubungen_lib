# Library Management System API

This is a RESTful API for managing a library system, built with PHP, the Slim Framework, and JWT (JSON Web Token) for secure authentication. The API allows users to manage authors, books, and the relationships between them, providing a streamlined solution for library operations.

## Features

- **User Management**: Register and authenticate users, ensuring secure access through JWT tokens.
- **Protected Endpoints**: Utilize middleware for token verification, regeneration, and blacklist management for expired tokens.
- **CRUD Functionality**:
  - Add and list authors.
  - Add and list books.
  - Establish relationships between books and authors.

## Technology Stack

- **PHP**: Backend logic and scripting.
- **Slim Framework**: Lightweight framework for RESTful API development.
- **JWT (Firebase/JWT)**: Secure user authentication and token handling.
- **MySQL**: Database for managing users, authors, and books.
- **SQLyog**: Database management tool.

---

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
Response:

Success:
json
Copy code
{
  "status": "success",
  "token": null,
  "data": null
}
Failure:
json
Copy code
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

json
Copy code
{
  "username": "yourUsername",
  "password": "yourPassword"
}
Response:

Success:
json
Copy code
{
  "status": "success",
  "token": "your_jwt_token",
  "data": null
}
Failure:
json
Copy code
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

json
Copy code
{
  "name": "Author Name"
}
Response:

json
Copy code
{
  "status": "success",
  "token": "new_jwt_token",
  "data": null
}
Get List of Authors
Method: GET
Endpoint: /authors

Response:

json
Copy code
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

json
Copy code
{
  "title": "Book Title",
  "author_id": 1
}
Get List of Books
Method: POST
Endpoint: /books

Response:

json
Copy code
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

json
Copy code
{
  "book_id": 1,
  "author_id": 1
}
Response:

json
Copy code
{
  "status": "success",
  "token": "new_jwt_token",
  "data": null
}
Get List of Book-Author Relationships
Method: GET
Endpoint: /books/authors

Response:

json
Copy code
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
5. Authorization
Include the JWT in the request headers as follows:

json
Copy code
{
  "Authorization": "Bearer {your_jwt_token}"
}
How It Works
Endpoints: Clearly outlined with methods and paths.
Request/Response: Each API call includes detailed JSON examples for clarity.
Authentication: Secure access with JWT for protected routes.
This documentation ensures developers can quickly integrate and utilize the Library Management System API effectively.
