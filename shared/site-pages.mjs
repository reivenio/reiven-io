export const SITE_ORIGIN = 'https://reiven.io';

export const PUBLIC_PAGE_PATHS = Object.freeze([
  '/',
  '/encrypted-file-sharing',
  '/encrypted-notes',
  '/security',
  '/privacy',
  '/about',
  '/cli',
  '/guides',
  '/guides/share-password-protected-files',
  '/guides/memory-only-storage',
  '/guides/encrypted-qr-sharing',
]);

export const SITE_SCHEMA = JSON.stringify({
  '@context': 'https://schema.org',
  '@type': 'WebSite',
  name: 'Reiven.io',
  alternateName: 'Reiven',
  url: `${SITE_ORIGIN}/`,
});
