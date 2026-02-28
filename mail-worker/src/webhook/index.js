// Webhook Module - Consolidates all webhook functionality
// This module handles:
// - Resend webhooks (email status updates)
// - Webhook event log API (admin interface for viewing event logs)

// Import to register API routes
import './webhook-api';

// Re-export resend service for convenience
export { default as resendService } from '../service/resend-service';
