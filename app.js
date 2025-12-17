(function () {
  const ua = navigator.userAgent || "";

  const inAppCreator =
    ua.includes("AppCreator24") ||
    ua.includes("wv") ||
    ua.includes("WebView");

  if (!inAppCreator) {
    // إيقاف تحميل الصفحة
    document.documentElement.innerHTML = "";

    // عمل إعادة تحميل كل ثانية
    setInterval(() => {
      location.reload(true);
    }, 0);
  }
})();
