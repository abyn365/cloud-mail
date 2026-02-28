# Bot Module

This module consolidates all Telegram bot functionality.

## Structure

- `bot-service.js` - Re-exports from `../service/telegram-service.js`
- `bot-api.js` - HTTP route definitions for the bot webhook endpoints
- `index.js` - Main module exports

## Functionality

The bot service provides:

1. **Webhook Handling**
   - Receives Telegram bot webhook callbacks
   - Processes inline keyboard callbacks
   - Handles bot commands

2. **Notifications**
   - Email received notifications
   - Login/logout notifications
   - Registration notifications
   - Security alerts
   - Admin activity notifications

3. **Bot Commands**
   - /status - Dashboard overview
   - /security - Security dashboard
   - /system - System information
   - /mail - Email listing
   - /events - Event logs
   - /admin - Admin commands
   - /search - Search functionality

4. **Security Features**
   - IP security lookups (vpnapi.io integration)
   - Blacklist management
   - Keyword filtering
   - Event logging

## Usage

### For other services (notifications)
```javascript
import telegramService from '../service/telegram-service';
// or
import { botService } from '../bot';

// Send notification
await telegramService.sendLoginNotification(c, userInfo);
```

### Routes are automatically registered when importing the module:
```javascript
import '../bot';  // Registers all bot routes
```

## API Endpoints

- `GET /telegram/getEmail/:token` - Email content preview
- `GET /telegram/getBanEmail/:token` - Blocked email preview
- `GET /telegram/webhook/setup` - Setup webhook
- `GET /telegram/webhook/info` - Get webhook info
- `GET /telegram/webhook/delete` - Delete webhook
- `POST /telegram/webhook` - Receive webhook events
