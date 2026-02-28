// Bot Module - Consolidates all Telegram bot functionality
// This module provides Telegram bot webhook handling and notifications

// Re-export all notification functions from the original telegram-service
// This allows other services to import from either location
export { default } from './bot-service';
export { default as botService } from './bot-service';

// API routes are registered via bot-api.js
import './bot-api';
