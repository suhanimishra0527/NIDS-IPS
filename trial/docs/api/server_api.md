# Server REST API Specification

<!-- TODO: Full API documentation for the central server -->

## Authentication

- Agent JWT: `Authorization: Bearer <token>`
- Admin: `X-Admin-Key: <key>`

## Endpoints

<!-- TODO: Document each endpoint with request/response examples -->

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | /api/register | Registration Key | Register agent |
| POST | /api/heartbeat | Agent JWT | Agent heartbeat |
| POST | /api/alerts | Agent JWT | Submit alerts |
| GET | /api/global_blocklist | Agent JWT | Get blocklist |
| GET | /api/dashboard/summary | None | Dashboard data |
