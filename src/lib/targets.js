// Every address outside the home network that the connection check contacts. Nothing else is
// contacted, apart from a website the person asks check_website about. Nothing is uploaded: these
// are pings, DNS questions, one plain-HTTP request that should come back empty, and one secure
// connection that is closed as soon as it opens.

/** Pinged to measure the leg from the router out to the internet. Both are large anycast DNS services. */
export const INTERNET_HOSTS = [
  { ip: "1.1.1.1", label: "Cloudflare" },
  { ip: "8.8.8.8", label: "Google" },
];

/** Public DNS services, asked the same questions as this computer's own DNS server, for comparison. */
export const PUBLIC_DNS = [
  { ip: "1.1.1.1", label: "Cloudflare DNS" },
  { ip: "8.8.8.8", label: "Google DNS" },
];

/** A name that always exists, used to check that lookups work at all. */
export const KNOWN_NAME = "one.one.one.one";

/** Random names under this domain must not exist; an answer means the DNS server makes them up. */
export const MISSING_NAME_DOMAIN = "example.com";

/** Answers 204 with an empty body. Anything else means a sign-in page or something in the way. */
export const CAPTIVE_URL = "http://cp.cloudflare.com/generate_204";

/** One secure connection, opened and closed, to see whether secure web traffic gets through. */
export const HTTPS_HOST = { ip: "1.1.1.1", servername: "one.one.one.one" };

/** Reached over IPv6 only when this computer has a public IPv6 address. */
export const IPV6_HOST = { ip: "2606:4700:4700::1111", port: 443 };

export const USER_AGENT = "home-net-doctor (+https://github.com/getlarkwright/home-net-doctor)";
