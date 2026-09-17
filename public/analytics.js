window.dataLayer = window.dataLayer || [];

function gtag() {
  window.dataLayer.push(arguments);
}

gtag('js', new Date());

const pathname = window.location.pathname;
const pagePath = pathname.startsWith('/delete/')
  ? '/delete'
  : pathname === '/download.html'
    ? '/download'
    : pathname;
const pageLocation = `${window.location.origin}${pagePath}`;

gtag('set', {
  page_location: pageLocation,
  page_path: pagePath,
});

gtag('config', 'G-MY4DKRSGEJ', {
  allow_ad_personalization_signals: false,
  allow_google_signals: false,
  page_location: pageLocation,
  page_path: pagePath,
  send_page_view: false,
});

gtag('event', 'page_view', {
  page_location: pageLocation,
  page_path: pagePath,
  page_title: document.title,
});
