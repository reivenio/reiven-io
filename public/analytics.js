(() => {
  const canTrackPage = () => window.location.hostname === 'reiven.io'
    && !window.location.search
    && !window.location.hash
    && document.body.classList.contains('public-page');

  const initializeAnalytics = () => {
    if (!canTrackPage()) return;
    const canonical = document.querySelector('link[rel="canonical"]')?.href;
    if (canonical !== `${window.location.origin}${window.location.pathname}`) return;
    window.dataLayer = window.dataLayer || [];
    window.gtag = function () { window.dataLayer.push(arguments); };
    window.gtag('js', new Date());
    window.gtag('set', {
      page_location: canonical,
      page_path: window.location.pathname,
      page_referrer: '',
    });
    window.gtag('config', 'G-MY4DKRSGEJ', {
      allow_ad_personalization_signals: false,
      allow_google_signals: false,
      page_location: canonical,
      page_referrer: '',
      send_page_view: false,
    });
    window.gtag('event', 'page_view', {
      page_location: canonical,
      page_path: window.location.pathname,
      page_referrer: '',
      page_title: document.title,
    });
    const script = document.createElement('script');
    script.async = true;
    script.src = 'https://www.googletagmanager.com/gtag/js?id=G-MY4DKRSGEJ';
    document.head.appendChild(script);
  };

  const scheduleAnalytics = () => {
    if (window.requestIdleCallback) {
      window.requestIdleCallback(initializeAnalytics, { timeout: 3000 });
    } else {
      window.setTimeout(initializeAnalytics, 0);
    }
  };
  if (document.readyState === 'complete') scheduleAnalytics();
  else window.addEventListener('load', scheduleAnalytics, { once: true });
})();
