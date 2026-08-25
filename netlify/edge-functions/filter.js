export default async (request, context) => {
  const url = new URL(request.url);

  // 1. Robots.txt check: Agar /robots.txt request ho to verification page par rewrite karein
  if (url.pathname === '/robots.txt') {
    return context.rewrite('/verification.html');
  }

  // 2. Static files aur verification.html ko bypass karein
  if (url.pathname === '/verification.html' || url.pathname.includes('.')) {
    return context.next();
  }

  const clientIP = context.ip || "";
  const userAgent = request.headers.get('user-agent') || "";
  
  // Netlify Edge context se Country aur ASN read karna
  const clientCountry = context.geo?.country?.code || "";
  const clientASN = context.account?.as_number ? String(context.account.as_number) : "";

  const BLOCKED_IPS = new Set([
    "13.57.148.235", "54.183.149.156", "44.243.111.67", "173.252.107.115", 
    "173.252.107.116", "173.252.107.12", "173.252.69.116", "173.252.69.4", 
    "173.252.70.33", "173.252.70.39", "173.252.70.42", "173.252.82.14", 
    "173.252.82.15", "173.252.82.22", "173.252.82.53", "173.252.87.28", 
    "173.252.87.3", "173.252.95.23", "173.252.95.27", "173.252.95.29", 
    "173.252.95.8", "69.171.231.26", "69.171.234.17", "69.63.184.29", 
    "69.63.184.35"
  ]);

  const BLOCKED_UAS = ["facebookexternalhit"];
  const BOT_ASNS = new Set(["32934", "16509", "15169"]);
  const BLOCKED_COUNTRIES = new Set(["SE", "IE"]);

  let triggerVerification = false;

  // 1. COUNTRY CHECK
  if (clientCountry && BLOCKED_COUNTRIES.has(clientCountry.toUpperCase())) {
    triggerVerification = true;
  }

  // 2. ASN Network Check
  if (!triggerVerification && clientASN && BOT_ASNS.has(clientASN)) {
    triggerVerification = true;
  }

  // 3. IP Check
  if (!triggerVerification && BLOCKED_IPS.has(clientIP)) {
    triggerVerification = true;
  }

  // 4. User-Agent Check
  if (!triggerVerification) {
    for (const ua of BLOCKED_UAS) {
      if (userAgent.toLowerCase().includes(ua.toLowerCase())) {
        triggerVerification = true;
        break;
      }
    }
  }

  // Criteria match hone par verification.html par rewrite karein
  if (triggerVerification) {
    return context.rewrite('/verification.html');
  }

  return context.next();
};
