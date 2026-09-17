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

gtag('config', 'G-MY4DKRSGEJ', {
  allow_ad_personalization_signals: false,
  allow_google_signals: false,
  send_page_view: false,
});

gtag('event', 'page_view', {
  page_location: `${window.location.origin}${pagePath}`,
  page_path: pagePath,
  page_title: document.title,
});
