"""
PicoCTF platform client.

Handles authentication, challenge listing, file downloads, and flag submission.
Built against the modern picoCTF platform (play.picoctf.org) which uses
django-allauth for auth and a Django REST API for challenges/submissions.
"""

import logging
import re
import time
from dataclasses import dataclass, field
from html import unescape
from pathlib import Path
from typing import Optional
import httpx

log = logging.getLogger(__name__)

# Category ID → name mapping (for filtering)
CATEGORY_MAP = {
    1: "web exploitation",
    2: "cryptography",
    3: "reverse engineering",
    4: "forensics",
    5: "general skills",
    6: "binary exploitation",
}

# Reverse lookup: common short names → category ID
CATEGORY_ALIASES = {
    "web": 1, "web exploitation": 1,
    "crypto": 2, "cryptography": 2,
    "rev": 3, "reverse engineering": 3, "reversing": 3,
    "forensics": 4,
    "general": 5, "general skills": 5, "misc": 5,
    "pwn": 6, "binary exploitation": 6, "binary": 6,
}


@dataclass
class Challenge:
    id: str
    name: str
    category: str
    points: int
    description: str
    hints: list[str] = field(default_factory=list)
    files: list[str] = field(default_factory=list)        # download URLs
    connection_info: Optional[str] = None                  # nc host port / URL
    solved: bool = False
    tags: list[str] = field(default_factory=list)
    on_demand: bool = False


class PicoCTFClient:
    """Interact with the picoCTF platform."""

    def __init__(self, base_url: str, username: str, password: str):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.client = httpx.Client(
            follow_redirects=True,
            timeout=30.0,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
                ),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            },
        )
        self._logged_in = False

    # ──────────────────────────── auth ────────────────────────────

    @property
    def _csrf_token(self) -> Optional[str]:
        """Extract CSRF token from cookies."""
        return self.client.cookies.get("csrftoken")

    def _csrf_headers(self) -> dict[str, str]:
        """Return headers with CSRF token for mutating requests."""
        headers = {}
        token = self._csrf_token
        if token:
            headers["X-CSRFToken"] = token
        return headers

    def login(self) -> bool:
        """Authenticate with picoCTF using django-allauth."""
        log.info("Logging in to %s as %s ...", self.base_url, self.username)

        # Step 1: Get initial CSRF cookie by hitting a known API endpoint
        # The /login page may be behind Cloudflare, but the allauth config
        # endpoint is an API route that reliably sets the csrftoken cookie.
        for init_url in [
            f"{self.base_url}/api/_allauth/browser/v1/config",
            f"{self.base_url}/api/challenges/?page_size=1",
            f"{self.base_url}/",
        ]:
            try:
                r = self.client.get(init_url)
                if self._csrf_token:
                    log.debug("Got CSRF token from %s", init_url)
                    break
            except Exception as e:
                log.debug("Init request to %s failed: %s", init_url, e)

        if not self._csrf_token:
            log.warning("Could not obtain CSRF token from any endpoint")

        # Step 2: Authenticate via allauth
        login_url = f"{self.base_url}/api/_allauth/browser/v1/auth/login"
        payload = {
            "username": self.username,
            "password": self.password,
        }

        r = self.client.post(
            login_url,
            json=payload,
            headers={
                **self._csrf_headers(),
                "Content-Type": "application/json",
                "Referer": f"{self.base_url}/login",
                "Origin": self.base_url,
            },
        )

        if r.status_code == 200:
            data = r.json()
            if data.get("status") == 200 or data.get("data", {}).get("user"):
                log.info("Login successful (allauth)")
                self._logged_in = True
                return True

        # Fallback: Check if already logged in via session
        if self._check_session():
            log.info("Already logged in via session")
            self._logged_in = True
            return True

        log.error("Login failed. Status %s, Response: %s", r.status_code, r.text[:500])
        return False

    def _check_session(self) -> bool:
        """Verify we have a valid session."""
        try:
            r = self.client.get(
                f"{self.base_url}/api/_allauth/browser/v1/auth/session"
            )
            if r.status_code == 200:
                data = r.json()
                user = data.get("data", {}).get("user")
                return user is not None
        except Exception:
            pass
        return False

    # ──────────────────────── challenges ──────────────────────────

    def get_challenges(self) -> list[Challenge]:
        """Fetch all available challenges (paginated)."""
        assert self._logged_in, "Must login first"

        challenges: list[Challenge] = []
        page = 1
        page_size = 100

        while True:
            url = f"{self.base_url}/api/challenges/?page_size={page_size}&page={page}"
            try:
                r = self.client.get(url)
                if r.status_code != 200:
                    log.error("Failed to fetch challenges page %d: %s", page, r.status_code)
                    break

                data = r.json()
                results = data.get("results", [])
                if not results:
                    break

                for raw in results:
                    challenges.append(self._parse_challenge_list_item(raw))

                log.info(
                    "Fetched page %d: %d challenges (total so far: %d / %d)",
                    page, len(results), len(challenges), data.get("count", "?"),
                )

                if not data.get("next"):
                    break
                page += 1

            except Exception as e:
                log.error("Error fetching challenges page %d: %s", page, e)
                break

        return challenges

    def get_challenge_instance(self, challenge_id: str) -> dict:
        """Fetch the instance details for a challenge (description, hints, endpoints)."""
        url = f"{self.base_url}/api/challenges/{challenge_id}/instance/"
        r = self.client.get(url)
        if r.status_code == 200:
            return r.json()
        log.warning("Failed to get instance for challenge %s: %s", challenge_id, r.status_code)
        return {}

    def start_instance(self, challenge_id: str) -> bool:
        """Start an on-demand challenge instance."""
        url = f"{self.base_url}/api/challenges/{challenge_id}/instance/"
        r = self.client.put(
            url,
            json={"action": "start"},
            headers={
                **self._csrf_headers(),
                "Content-Type": "application/json",
            },
        )
        if r.status_code == 204:
            log.info("Started instance for challenge %s", challenge_id)
            return True
        log.warning("Failed to start instance for %s: %s", challenge_id, r.status_code)
        return False

    def stop_instance(self, challenge_id: str) -> bool:
        """Stop an on-demand challenge instance."""
        url = f"{self.base_url}/api/challenges/{challenge_id}/instance/"
        r = self.client.put(
            url,
            json={"action": "stop"},
            headers={
                **self._csrf_headers(),
                "Content-Type": "application/json",
            },
        )
        if r.status_code == 204:
            log.info("Stopped instance for challenge %s", challenge_id)
            return True
        log.warning("Failed to stop instance for %s: %s", challenge_id, r.status_code)
        return False

    def enrich_challenge(self, challenge: Challenge) -> Challenge:
        """
        Fetch the instance data and enrich the challenge with
        description, hints, files, and connection info.
        """
        instance = self.get_challenge_instance(challenge.id)
        if not instance:
            return challenge

        # If on-demand and not running, start it
        if instance.get("on_demand") and instance.get("status") == "NOT_RUNNING":
            log.info("Challenge '%s' is on-demand — starting instance...", challenge.name)
            if self.start_instance(challenge.id):
                # Re-fetch instance after starting
                time.sleep(3)
                instance = self.get_challenge_instance(challenge.id)

        challenge.on_demand = instance.get("on_demand", False)
        challenge.description = self._clean_html(instance.get("description", ""))

        # Parse hints (they come as HTML strings)
        raw_hints = instance.get("hints", [])
        challenge.hints = [self._clean_html(h) for h in raw_hints if h]

        # Extract file download URLs from description HTML
        desc_html = instance.get("description", "")
        challenge.files = self._extract_file_urls(desc_html)

        # Extract connection info (URLs/endpoints in description)
        challenge.connection_info = self._extract_connection_info(desc_html)

        return challenge

    def _parse_challenge_list_item(self, raw: dict) -> Challenge:
        """Parse a challenge from the /api/challenges/ list response."""
        category_obj = raw.get("category", {})
        category_name = category_obj.get("name", "unknown") if isinstance(category_obj, dict) else str(category_obj)

        tags = []
        for t in raw.get("tags", []):
            if isinstance(t, dict):
                tags.append(t.get("name", ""))
            else:
                tags.append(str(t))

        return Challenge(
            id=str(raw.get("id", "")),
            name=raw.get("name", "Unknown"),
            category=category_name.lower(),
            points=int(raw.get("event_points", 0)),
            description="",  # Populated later by enrich_challenge
            hints=[],
            files=[],
            connection_info=None,
            solved=bool(raw.get("solved_by_user", False)),
            tags=tags,
            on_demand=False,  # Populated later by enrich_challenge
        )

    @staticmethod
    def _extract_file_urls(html: str) -> list[str]:
        """Extract file download URLs from description HTML."""
        # Match <a href="..." download> links (challenge files)
        urls = re.findall(
            r'<a\s[^>]*href=[\'"]([^\'"]+)[\'"][^>]*download[^>]*>',
            html, re.IGNORECASE
        )
        # Also match links to challenge-files.picoctf.net without download attribute
        urls += re.findall(
            r'href=[\'\"](https?://challenge-files\.picoctf\.net/[^\'\"\s]+)[\'"]',
            html, re.IGNORECASE
        )
        # Deduplicate while preserving order
        seen = set()
        unique = []
        for u in urls:
            if u not in seen:
                seen.add(u)
                unique.append(u)
        return unique

    @staticmethod
    def _extract_connection_info(html: str) -> Optional[str]:
        """Extract connection info (URLs, nc commands) from description HTML."""
        # Look for non-picoctf.net URLs (challenge endpoints)
        endpoint_urls = re.findall(
            r'href=[\'\"](https?://[^\'"]+picoctf\.net[^\'"]*)[\'"]',
            html, re.IGNORECASE
        )
        # Filter out challenge-files URLs (those are download links, not endpoints)
        endpoints = [u for u in endpoint_urls if "challenge-files" not in u]

        # Also look for nc commands
        nc_matches = re.findall(r'nc\s+\S+\s+\d+', html)

        parts = endpoints + nc_matches
        return "; ".join(parts) if parts else None

    @staticmethod
    def _clean_html(html: str) -> str:
        """Strip HTML tags and decode entities for display."""
        # Remove tags
        text = re.sub(r'<[^>]+>', '', html)
        # Decode HTML entities
        text = unescape(text)
        # Normalize whitespace
        text = re.sub(r'\s+', ' ', text).strip()
        return text

    # ──────────────────── file downloads ─────────────────────────

    def download_challenge_files(self, challenge: Challenge, dest_dir: Path) -> list[Path]:
        """Download all files for a challenge into dest_dir."""
        dest_dir.mkdir(parents=True, exist_ok=True)
        downloaded = []
        for url in challenge.files:
            if not url.startswith("http"):
                url = f"{self.base_url}{url}"
            try:
                r = self.client.get(url)
                fname = self._filename_from_response(r, url)
                path = dest_dir / fname
                path.write_bytes(r.content)
                downloaded.append(path)
                log.info("Downloaded %s → %s (%d bytes)", url, path, len(r.content))
            except Exception as e:
                log.warning("Failed to download %s: %s", url, e)
        return downloaded

    @staticmethod
    def _filename_from_response(response: httpx.Response, url: str) -> str:
        cd = response.headers.get("content-disposition", "")
        match = re.search(r'filename="?([^";\n]+)"?', cd)
        if match:
            return match.group(1).strip()
        return url.rstrip("/").split("/")[-1].split("?")[0] or "download"

    # ──────────────────── flag submission ─────────────────────────

    def submit_flag(self, challenge: Challenge, flag: str) -> bool:
        """Submit a flag for a challenge. Returns True if accepted."""
        log.info("Submitting flag for '%s': %s", challenge.name, flag)

        url = f"{self.base_url}/api/submissions/"
        payload = {
            "challenge": int(challenge.id),
            "flag": flag,
        }

        try:
            r = self.client.post(
                url,
                json=payload,
                headers={
                    **self._csrf_headers(),
                    "Content-Type": "application/json",
                },
            )
            if r.status_code == 200 or r.status_code == 201:
                data = r.json()
                if data.get("correct"):
                    log.info("✅ Flag ACCEPTED for '%s'", challenge.name)
                    return True
                elif data.get("correct") is False:
                    log.warning("❌ Flag REJECTED for '%s'", challenge.name)
                    return False
                elif data.get("historical"):
                    log.info("Already solved '%s'", challenge.name)
                    return True
            log.warning("Unexpected submission response: %s %s", r.status_code, r.text[:300])
        except Exception as e:
            log.error("Failed to submit flag for '%s': %s", challenge.name, e)

        return False

    def close(self):
        self.client.close()
