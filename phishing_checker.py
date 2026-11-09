"""Phishing URL Awareness Checker for offline, educational use."""

import ipaddress
import re
from urllib.parse import SplitResult, urlsplit


# Explanation: These are the workbook's thresholds for two text-based clues.
LONG_URL_LENGTH = 100
MANY_HOSTNAME_LABELS = 5

EXPLICIT_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.IGNORECASE)
IPV4_SHAPE = re.compile(r"[0-9]+(?:\.[0-9]+){3}")


def parse_web_url(url: str) -> tuple[SplitResult, str]:
    """Split a sample URL and check that it has a usable web hostname."""
    if "\\" in url or any(char.isspace() or not char.isprintable() for char in url):
        raise ValueError("Remove internal whitespace, invisible characters, or backslashes.")

    if re.match(r"^https?:(?!//)", url, re.IGNORECASE):
        raise ValueError("Use http:// or https:// before the hostname.")

    # Explanation: A leading // tells urlsplit where the authority begins.
    # Leaving the scheme empty avoids inventing an HTTP warning.
    has_authority_prefix = bool(EXPLICIT_SCHEME.match(url)) or url.startswith("//")
    candidate = url if has_authority_prefix else "//" + url

    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        # Explanation: Accessing .port checks its format and allowed range.
        _ = parsed.port
    except ValueError as error:
        raise ValueError("Check the hostname, IPv6 brackets, or port number.") from error

    if parsed.scheme not in ("", "http", "https"):
        raise ValueError("Use an HTTP or HTTPS sample URL.")

    if not hostname:
        raise ValueError("Could not identify a hostname.")

    if not has_authority_prefix and parsed.password is not None:
        raise ValueError("Use an explicit HTTP or HTTPS scheme with user information.")

    # Explanation: Authority can include user information and a port.
    # Only the part after the last @ can contain the destination hostname.
    host_and_port = parsed.netloc.rsplit("@", 1)[-1]
    if host_and_port.endswith(":"):
        raise ValueError("Enter a port number after the colon.")

    if "[" in host_and_port or "]" in host_and_port:
        bracketed_host = re.fullmatch(r"\[[^\[\]]+\](?::[0-9]+)?", host_and_port)
        if not bracketed_host or ":" not in hostname or "%" in hostname:
            raise ValueError("Use square brackets around a plain IPv6 address.")

    return parsed, hostname


def inspect_url(raw_url: str) -> list[str]:
    """Return the checker messages as a list, as in the starter program."""
    url = raw_url.strip()
    if not url:
        return ["No URL entered."]

    try:
        parsed, hostname = parse_web_url(url)
    except ValueError as error:
        return [f"Invalid input: {error}"]

    # Explanation: A single trailing dot can mark a fully qualified domain name.
    host_for_checks = hostname if ":" in hostname else hostname.removesuffix(".")

    # Explanation: ipaddress checks actual IPv4 and IPv6 values, including
    # numeric ranges that a digit-pattern check would miss.
    try:
        address = ipaddress.ip_address(host_for_checks)
    except ValueError:
        address = None

    labels: list[str] = []
    if address is None:
        if IPV4_SHAPE.fullmatch(host_for_checks):
            return ["Invalid input: the hostname looks like an invalid IPv4 address."]

        # Explanation: IDNA encoding gives us ASCII labels for basic syntax
        # checks. The output still shows the hostname parsed from the input.
        try:
            ascii_hostname = host_for_checks.encode("idna").decode("ascii")
        except UnicodeError:
            return ["Invalid input: the hostname could not be interpreted as a domain name."]

        labels = ascii_hostname.split(".")
        if len(ascii_hostname) > 253 or not all(DNS_LABEL.fullmatch(label) for label in labels):
            return ["Invalid input: the hostname contains invalid domain labels."]

    warnings = []

    # Explanation: @ in a path or query has no role in selecting the host.
    if "@" in parsed.netloc:
        warnings.append("Contains an @ symbol in the authority. Check the hostname after it.")

    # Explanation: Count the text the user entered, before adding // for parsing.
    if len(url) > LONG_URL_LENGTH:
        warnings.append(f"Unusually long URL (over {LONG_URL_LENGTH} characters).")

    if address is not None:
        warnings.append(f"Uses an IPv{address.version} address instead of a domain name.")

    # Explanation: Count DNS labels only. IPv4 address octets are not labels.
    if len(labels) >= MANY_HOSTNAME_LABELS:
        warnings.append(f"Contains many hostname segments ({len(labels)} labels).")

    # Explanation: xn-- matters at the beginning of a label. Unicode names
    # can also contain look-alike letters, and both forms have legitimate uses.
    if not hostname.isascii():
        warnings.append("Contains Unicode in the hostname. Check it for look-alike letters.")
    elif any(label.startswith("xn--") for label in labels):
        warnings.append("Contains a punycode-style hostname label. Check it for look-alike letters.")

    if parsed.scheme == "http":
        warnings.append("Uses HTTP. HTTPS alone does not prove trust.")

    # Explanation: Keep the hostname visible and escape Unicode so that a
    # look-alike character is easier to spot. Avoid echoing the full URL.
    findings = [f"Parsed hostname: {ascii(hostname)}"]
    if not parsed.scheme:
        findings.append("No scheme specified. HTTP or HTTPS could not be inferred from the text.")

    if warnings:
        findings.append(f"REVIEW CAREFULLY: {len(warnings)} warning sign(s) found.")
        findings.extend(warnings)
    else:
        findings.append("No listed warning signs found. This does NOT prove safety.")

    return findings


def main() -> None:
    print("EWB Phishing URL Awareness Checker")
    print("Educational use only. The checker analyzes text locally.")
    print("Use synthetic sample URLs. Type q to quit.")

    # Explanation: The loop lets students run several samples in one session.
    while True:
        try:
            raw_url = input("\nEnter a sample URL: ")
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye.")
            break

        if raw_url.strip().lower() in {"q", "quit", "exit"}:
            print("Goodbye.")
            break

        print("\nResult:")
        for message in inspect_url(raw_url):
            print(f"- {message}")


# Explanation: Importing inspect_url for testing will leave the prompt closed.
if __name__ == "__main__":
    main()
