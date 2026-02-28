// DEPRECATED: This file has been moved to the bot/ module
// Routes are now registered in ../bot/bot-api.js and imported via ../bot/index.js
//
// The bot service functionality has been consolidated in the bot/ module:
// - ../bot/bot-service.js - Core bot service (re-exports from ../service/telegram-service.js)
// - ../bot/bot-api.js - HTTP route definitions for the bot
// - ../bot/index.js - Module exports
//
// For backward compatibility, import from '../bot' instead of this file.
// This file no longer registers any routes to prevent double registration.
