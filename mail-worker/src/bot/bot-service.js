// Bot Service Module
// This module provides Telegram bot functionality including:
// - Webhook handling for bot commands
// - Notification sending to Telegram
// - Chat management and security
// - IP security lookups
// - Event logging

// Re-export everything from telegram-service.js for backward compatibility
// The original telegram-service.js contains all the bot functionality
export { default } from '../service/telegram-service';
export { default as botService } from '../service/telegram-service';
