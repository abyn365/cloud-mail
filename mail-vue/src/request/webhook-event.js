import http from '@/axios/index.js'

export function webhookEventList(params) {
	return http.get('/webhook-event/list', { params });
}

export function webhookEventDetail(eventId) {
	return http.get('/webhook-event/detail', { params: { eventId } });
}
