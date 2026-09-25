(() => {
  const routes = new Map([
    ['#share', '/share'], ['#note', '/share#note'],
    ['#download', '/receive'], ['#cli', '/cli'],
  ]);
  const redirectLegacyRoute = () => {
    const target = routes.get(window.location.hash);
    if (target) window.location.replace(target);
  };
  window.addEventListener('hashchange', redirectLegacyRoute);
  redirectLegacyRoute();
})();
