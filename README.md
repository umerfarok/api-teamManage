﻿# Go API Example

This is an example of a Go API that uses Gin and MongoDB. The API provides basic user registration, login, and user management functionalities.

## Prerequisites

- Go (version x.x.x)
- MongoDB (version x.x.x)

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/your-username/your-repository.git

cd your-repository
go mod download

go run main.go
## API Endpoints
## User Registration
## Endpoint: POST /register

Description: Registers a new user.

## Request Body:

{
  "name": "Umer Farooq",
  "email": "Umer@example.com",
  "password": "password123",
  "date": "2023-07-01",
  "teamName": "Team A",
  "money": 100
}
## Response 
{
  "message": "User registered successfully"
}
## User Login
## Endpoint: POST /login

Description: Logs in a user and returns a JWT token.

Request Body:
{
  "email": "Umer@example.com",
  "password": "password123"
}

response
{
  "token": "your-jwt-token"
}
Get Users
## Endpoint: GET /users

Description: Retrieves all users.

Authorization Header: Bearer Token

Response:
[
  {
    "id": "user-id",
    "name": "Umer",
    "email": "Umer@example.com",
    "date": "2023-07-01",
    "teamName": "Team A",
    "money": 100
  },
  // ...
]
## Update User
Endpoint: PATCH /users/:userId

Description: Updates a user's money balance.

Authorization Header: Bearer Token

Request Body:
{
  "money": 200
}
