self.addEventListener('notificationclick', (event) => {
  event.notification.close();

  const targetUrl = event.notification?.data?.url || '/inbox';
  const absoluteUrl = new URL(targetUrl, self.location.origin).href;

  event.waitUntil((async () => {
    const windowClients = await self.clients.matchAll({
      type: 'window',
      includeUncontrolled: true,
    });

    if (windowClients.length > 0) {
      for (const client of windowClients) {
        client.postMessage({
          type: 'OPEN_INBOX_FROM_NOTIFICATION',
          url: targetUrl,
        });

        if ('focus' in client) {
          await client.focus();
        }
      }
      return;
    }

    if (self.clients.openWindow) {
      await self.clients.openWindow(absoluteUrl);
    }
  })());
});
