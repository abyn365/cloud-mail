# Webhook Module

This module consolidates all webhook functionality for email service integrations and event logging.

## Structure

- `webhook-api.js` - HTTP route definitions for webhooks
- `index.js` - Main module exports

## Functionality

### 1. Resend Webhooks (`POST /webhooks`)

Handles email status updates from Resend (email service provider):

- `email.delivered` - Email successfully delivered
- `email.complained` - Recipient marked as spam
- `email.bounced` - Email bounced
- `email.delivery_delayed` - Delivery delayed
- `email.failed` - Send failed

Updates the email status in the database accordingly.

### 2. Webhook Event Log API

Admin interface for viewing system event logs:

- `GET /webhook-event/list` - List event logs with pagination and search
- `GET /webhook-event/detail` - Get single event details

Events logged include:
- Email events (received, sent, delivered, bounced)
- Authentication events (login, logout, failed attempts)
- Admin actions (user management, role changes)
- Security events (IP changes, blacklist blocks)

## Usage

### Register webhook routes:
```javascript
import '../webhook';  // Registers all webhook routes
```

### Use resend service:
```javascript
import resendService from '../service/resend-service';

// Process webhook
await resendService.webhooks(c, body);
```

## API Endpoints

### Resend Webhook
- `POST /webhooks` - Receive Resend webhook events

### Webhook Event Log
- `GET /webhook-event/list?page=1&size=20&eventId=0&keyword=` - List events
- `GET /webhook-event/detail?eventId=123` - Get event detail
