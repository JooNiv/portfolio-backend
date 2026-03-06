# Portfolio Backend

A Rust backend service for managing notes, using PostgreSQL and Docker.

## Features

- RESTful API for notes (add, get, delete)
- JWT-based authentication
- PostgreSQL database integration
- Dockerized for easy deployment

## Project Structure

```
.
├── .env                # Environment variables
├── Cargo.toml          # Rust dependencies and metadata
├── compose.yml         # Docker Compose configuration
├── Dockerfile          # Docker build instructions
├── migrations/         # SQL migrations for database setup
│   └── 1_create_notes_table.up.sql
├── src/
│   └── main.rs         # Main application source
└── README.md           # Project documentation
```

## Getting Started

### Docker

Docker compose will manage everything for you

```sh
docker compose up --build
```

### Manually

#### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install)
- [Docker](https://docs.docker.com/get-docker/)
- [PostgreSQL](https://www.postgresql.org/download/)

#### Setup

1. **Clone the repository:**
   ```sh
   git clone git@github.com:JooNiv/portfolio-backend.git
   cd portfolio-backend
   ```

2. **Configure environment variables:**
   - Copy `.env.example` to `.env` and update values as needed.

3. **Run with Docker Compose:**
   ```sh
   docker compose up --build
   ```

4. **Run locally (without Docker):**
   ```sh
   cargo run
   ```

## API Endpoints

- `POST /login` - Authenticate and receive a JWT
- `GET /login`- Check validity of JWT
- `POST /notes` - Add a new note (requires JWT)
- `GET /notes` - Retrieve all notes
- `DELETE /notes/:id` - Delete a note by ID (requires JWT)