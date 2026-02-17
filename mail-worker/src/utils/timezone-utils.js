import dayjs from 'dayjs';
import utc from 'dayjs/plugin/utc';
import timezone from 'dayjs/plugin/timezone';

dayjs.extend(utc);
dayjs.extend(timezone);

const timezoneUtils = {
	
	/**
	 * Mendapatkan timezone dari IP address menggunakan ipapi.co
	 * @param {string} ip - IP address
	 * @returns {Promise<string>} - Timezone (e.g., 'Asia/Jakarta')
	 */
	async getTimezoneFromIP(ip) {
		// Skip untuk localhost/private IPs
		if (!ip || ip === '127.0.0.1' || ip.startsWith('192.168.') || ip.startsWith('10.') || ip === '::1') {
			return null;
		}

		try {
			// Gunakan ipapi.co (gratis, tidak perlu API key)
			const response = await fetch(`https://ipapi.co/${ip}/timezone/`, {
				headers: {
					'User-Agent': 'CloudMail/1.0'
				}
			});

			if (response.ok) {
				const timezone = await response.text();
				// Validate timezone
				if (timezone && timezone.includes('/')) {
					return timezone.trim();
				}
			}
		} catch (e) {
			console.error('Failed to get timezone from IP:', e);
		}

		return null;
	},

	/**
	 * Mendapatkan timezone dari Cloudflare request headers
	 * @param {object} c - Hono context
	 * @returns {string|null} - Timezone dari CF headers
	 */
	getTimezoneFromCF(c) {
		// Cloudflare menyediakan timezone di header cf-timezone
		const cfTimezone = c.req.header('cf-timezone');
		if (cfTimezone) {
			return cfTimezone;
		}

		// Alternatif: dari cf-ipcountry
		const country = c.req.header('cf-ipcountry');
		if (country) {
			// Mapping sederhana country code ke timezone
			const countryTimezones = {
				'ID': 'Asia/Jakarta',
				'SG': 'Asia/Singapore',
				'MY': 'Asia/Kuala_Lumpur',
				'US': 'America/New_York',
				'GB': 'Europe/London',
				'JP': 'Asia/Tokyo',
				'AU': 'Australia/Sydney',
				'IN': 'Asia/Kolkata',
				'CN': 'Asia/Shanghai',
				'KR': 'Asia/Seoul',
				'TH': 'Asia/Bangkok',
				'PH': 'Asia/Manila',
				'VN': 'Asia/Ho_Chi_Minh',
				'DE': 'Europe/Berlin',
				'FR': 'Europe/Paris',
				'BR': 'America/Sao_Paulo',
				'RU': 'Europe/Moscow',
				'AE': 'Asia/Dubai',
				'SA': 'Asia/Riyadh',
				'TR': 'Europe/Istanbul'
			};
			
			return countryTimezones[country] || null;
		}

		return null;
	},

	/**
	 * Mendapatkan timezone dengan fallback
	 * Prioritas: CF headers -> IP API -> UTC
	 * @param {object} c - Hono context
	 * @param {string} ip - IP address
	 * @returns {Promise<string>} - Timezone
	 */
	async getTimezone(c, ip) {
		// Try Cloudflare headers first (fastest)
		const cfTimezone = this.getTimezoneFromCF(c);
		if (cfTimezone) {
			return cfTimezone;
		}

		// Try IP API (slower but more accurate)
		const ipTimezone = await this.getTimezoneFromIP(ip);
		if (ipTimezone) {
			return ipTimezone;
		}

		// Fallback to UTC
		return null;
	},

	/**
	 * Format waktu dengan dual timezone
	 * @param {string} timestamp - ISO timestamp
	 * @param {string|null} userTimezone - User timezone
	 * @returns {string} - Formatted time string
	 */
	formatDualTime(timestamp, userTimezone = null) {
		const utcTime = dayjs(timestamp).utc().format('YYYY-MM-DD HH:mm:ss');
		
		if (userTimezone) {
			try {
				const localTime = dayjs(timestamp).tz(userTimezone).format('YYYY-MM-DD HH:mm:ss');
				const offset = dayjs(timestamp).tz(userTimezone).format('Z');
				return `⏰ Server (UTC): ${utcTime}\n🌍 Local (${userTimezone} UTC${offset}): ${localTime}`;
			} catch (e) {
				console.error('Invalid timezone:', userTimezone, e);
			}
		}
		
		return `⏰ Time (UTC): ${utcTime}`;
	}

};

export default timezoneUtils;
