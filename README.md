# Pentest Automation Platform

Automated Penetration Testing Platform with FastAPI backend, React frontend, and Celery workers for distributed scanning.

## Features

- 🔍 Automated security scanning
- 📊 Report generation (PDF, HTML)
- 📱 Telegram notifications
- 💾 FTP report uploads
- 🚀 Distributed task processing with Celery
- 🐳 Docker containerized deployment
- 📈 Real-time scan monitoring

## Project Structure

```
pentest-automation/
├── backend/                # Python FastAPI backend
│   ├── api/               # API routes and endpoints
│   ├── core/              # Core configuration
│   ├── models/            # SQLAlchemy models
│   ├── schemas/           # Pydantic schemas
│   ├── db/                # Database configuration
│   ├── workers/           # Celery workers
│   └── alembic/           # Database migrations
├── frontend/              # React frontend (to be implemented)
├── cli/                   # CLI tool (to be implemented)
├── docker/                # Docker configurations
├── configs/               # Configuration files
└── scripts/               # Utility scripts
```

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Python 3.11+
- Node.js 20+ (for frontend)

### Setup

1. Clone the repository and copy environment file:

```bash
cp .env.example .env
```

2. Update the `.env` file with your configuration:
   - Set a strong `SECRET_KEY`
   - Configure database credentials
   - Add Telegram bot token (if using notifications)
   - Add FTP credentials (if using FTP uploads)

3. Build and start the services:

```bash
docker-compose up -d
```

4. Run database migrations:

```bash
docker-compose exec backend alembic upgrade head
```

5. Access the application:
   - API Documentation: http://localhost/api/docs
   - Frontend: http://localhost (when implemented)

## Development

### Backend Development

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Run the backend locally:

```bash
uvicorn backend.api.main:app --reload
```

3. Create a new migration:

```bash
alembic revision --autogenerate -m "description"
```

4. Apply migrations:

```bash
alembic upgrade head
```

### Celery Workers

Run Celery worker:

```bash
celery -A backend.workers.celery_app worker --loglevel=info
```

Run Celery beat (scheduler):

```bash
celery -A backend.workers.celery_app beat --loglevel=info
```

### Testing

```bash
pytest
```

### Code Formatting

```bash
black backend/
flake8 backend/
mypy backend/
```

## API Endpoints

### Health Check

- `GET /api/health` - Health check with database status
- `GET /api/ping` - Simple ping endpoint

### Targets

- `POST /api/targets` - Create a new target
- `GET /api/targets` - List all targets
- `GET /api/targets/{id}` - Get target details
- `PUT /api/targets/{id}` - Update target
- `DELETE /api/targets/{id}` - Delete target

### Scans

- `POST /api/scans` - Create and start a new scan
- `GET /api/scans` - List all scans
- `GET /api/scans/{id}` - Get scan details
- `DELETE /api/scans/{id}` - Delete scan

### Reports

- `GET /api/reports/{scan_id}/pdf` - Generate PDF report
- `GET /api/reports/{scan_id}/html` - Generate HTML report
- `POST /api/reports/{scan_id}/send-telegram` - Send report to Telegram
- `POST /api/reports/{scan_id}/upload-ftp` - Upload report to FTP

### Blacklist

- `POST /api/blacklist` - Add blacklist entry
- `GET /api/blacklist` - List blacklist entries
- `DELETE /api/blacklist/{id}` - Remove blacklist entry

## Architecture

### Services

- **PostgreSQL**: Main database for storing scans, targets, findings
- **Redis**: Message broker for Celery and caching
- **Backend API**: FastAPI REST API
- **Celery Worker**: Distributed task processing for scans
- **Celery Beat**: Periodic task scheduler
- **Frontend**: React application (to be implemented)
- **Nginx**: Reverse proxy

### Task Flow

1. User creates a scan via API
2. Backend validates target against blacklist
3. Scan task is queued in Celery
4. Worker picks up task and runs security tools
5. Results are stored in database
6. Report can be generated and sent via Telegram/FTP

## Configuration

Key environment variables:

- `DATABASE_URL` - PostgreSQL connection string
- `REDIS_URL` - Redis connection string
- `SECRET_KEY` - JWT secret key
- `TELEGRAM_BOT_TOKEN` - Telegram bot token
- `FTP_HOST`, `FTP_USER`, `FTP_PASSWORD` - FTP credentials
- `MAX_CONCURRENT_SCANS` - Maximum concurrent scans
- `SCAN_TIMEOUT` - Scan timeout in seconds

## License

MIT

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.
