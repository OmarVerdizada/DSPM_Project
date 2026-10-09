"""One answer to "is this a payment card number", for every detector that asks.

Three detectors used to decide this independently and disagree. Measured on this
tree before the change, a document reading `Device IMEI: 490154203237518` was
reported as a **CRITICAL** readable Primary Account Number, and so were a
Luhn-valid order id, a serial number of repeated digits, and a 16-digit
reference with no issuer prefix at all. The generic rule asked for a Luhn
checksum and nothing else; the PCI classifier scored a bare Luhn hit at 60
against a threshold of 55; only the GDPR detector required a payment word
nearby.

Luhn is not evidence. It accepts one in ten random digit strings by
construction, and it is the checksum used by IMEI numbers and several national
identifiers. What makes a number a card is the ISSUER PREFIX, the LENGTH THAT
ISSUER USES, and the COMPANY IT KEEPS - which is what every DLP product in the
category checks, and what this module checks in one place.

This module is stdlib-only and imports nothing from `classification`, so the
detectors can all reach it without an import cycle and without paying for the
compliance package's eager classifier imports.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# v2: a card is looked for inside a run that is not one as a whole, and a line break
# no longer joins two numbers into one run.
PAN_VALIDATOR_VERSION = "pan-validator-v2"

# 12-19 digits with at most one separator between them, not glued to another
# alphanumeric. The lookarounds are what keep a card out of a longer hex digest
# or account string. NBSP is in the separator class on purpose: text extracted
# from DOCX, PDF and OCR routinely uses it. A line break is not, and nor is any
# other vertical whitespace: through \s it was, and a column of four-digit codes
# on separate lines joined into "cards" - 4000..4159 read as ten issuer-valid
# PANs and a CRITICAL PCI finding. A card is written on one line.
PAN_CANDIDATE_RE = re.compile(r"(?<![A-Za-z0-9])(?:\d[ \t\u00a0-]?){11,18}\d(?![A-Za-z0-9])")
_DIGIT_GROUP_RE = re.compile(r"\d+")

# The window a supporting element has to appear in. 300 characters is Microsoft
# Purview's proximity for the credit-card sensitive information type, and it is
# a reasonable stand-in for "on the same record".
CONTEXT_WINDOW = 300

# Words that make a nearby number a card.
POSITIVE_CONTEXT = (
    "card number", "cardnumber", "card no", "cardno", "card #", "credit card", "debit card",
    "payment card", "cardholder", "card holder", "pan", "primary account number",
    "cvv", "cvc", "cvv2", "cvc2", "cid", "security code", "card verification",
    "expiry", "expires", "exp date", "expiration", "valid thru", "valid through",
    "visa", "mastercard", "master card", "amex", "american express", "discover",
    "jcb", "unionpay", "union pay", "maestro", "diners",
    "merchant", "acquirer", "issuer", "authorization", "authorisation", "settlement",
    "chargeback", "payment method", "billing", "checkout", "pos terminal", "emv",
    "track1", "track2", "track 1", "track 2", "service code", "bin range",
    # Safe now that terms match as whole words: "card" no longer finds
    # "discard", and "pan" no longer finds "company".
    "card", "cards", "pci", "payment", "payments", "transaction", "charge",
    "refund", "invoice card", "creditcard", "debitcard",
)

# Words that make a nearby number something else. An operational identifier in
# a spreadsheet is the single largest source of card false positives.
NEGATIVE_CONTEXT = (
    "imei", "imeisv", "meid", "esn", "iccid", "imsi", "serial number", "serial no",
    "asset tag", "order number", "order no", "order id", "invoice number", "invoice no",
    "tracking number", "tracking no", "waybill", "consignment", "reference number",
    "reference no", "ticket number", "customer number", "customer id", "account number",
    "membership", "loyalty", "barcode", "ean", "upc", "isbn", "sku", "part number",
    "phone", "mobile", "msisdn", "vin", "chassis", "policy number", "claim number",
    "employee number", "employee id", "badge", "meter number", "hash", "checksum",
)

# (prefix predicate, brand, accepted lengths). Order matters: the first match
# wins, so the longer, more specific prefixes come first.
_ISSUER_TABLE: tuple[tuple[re.Pattern[str], str, frozenset[int]], ...] = (
    (re.compile(r"^4"), "visa", frozenset({13, 16, 19})),
    (re.compile(r"^(5[1-5])"), "mastercard", frozenset({16})),
    (re.compile(r"^(22[2-9]\d|2[3-6]\d\d|27[01]\d|2720)"), "mastercard", frozenset({16})),
    (re.compile(r"^3[47]"), "amex", frozenset({15})),
    (re.compile(r"^(6011|65|64[4-9])"), "discover", frozenset({16, 19})),
    (re.compile(r"^35(2[89]|[3-8]\d)"), "jcb", frozenset({16, 17, 18, 19})),
    (re.compile(r"^62"), "unionpay", frozenset({16, 17, 18, 19})),
    (re.compile(r"^(30[0-5]|3095|36|38|39)"), "diners", frozenset({14, 15, 16, 17, 18, 19})),
    (re.compile(r"^(5018|5020|5038|5893|6304|6759|676[1-3]|50|5[6-9]|6[0-9])"), "maestro",
     frozenset({12, 13, 14, 15, 16, 17, 18, 19})),
)

# Published test numbers. Flagged, never dropped: a test card in production data
# is still a finding - it says the environment is carrying payment fixtures.
TEST_PAN_CATALOG = {
    "4111111111111111": "visa_test",
    "4012888888881881": "visa_test",
    "4222222222222": "visa_test",
    "5555555555554444": "mastercard_test",
    "5105105105105100": "mastercard_test",
    "2223003122003222": "mastercard_test",
    "378282246310005": "amex_test",
    "371449635398431": "amex_test",
    "6011111111111117": "discover_test",
    "6011000990139424": "discover_test",
    "3530111333300000": "jcb_test",
    "6200000000000005": "unionpay_test",
    "30569309025904": "diners_test",
    "38520000023237": "diners_test",
}

# A 15-digit IMEI is Luhn-valid by construction and its Type Allocation Code
# starts 01, 35, 44, 45, 49, 86 or 99. Those collide with nothing in the issuer
# table except Visa's bare "4", which does not use 15 digits anyway - so this is
# belt and braces for the case where a document says IMEI and means it.
_IMEI_TAC_PREFIXES = ("01", "35", "44", "45", "49", "86", "99")


@dataclass(frozen=True, slots=True)
class PanVerdict:
    """Why this digit run was accepted, and how strongly."""

    digits: str
    issuer: str
    issuer_valid: bool
    luhn_valid: bool
    confidence: str  # HIGH | MEDIUM | LOW
    context_terms: tuple[str, ...]
    negative_terms: tuple[str, ...]
    density: int
    test_card: str
    basis: str
    validator_version: str = PAN_VALIDATOR_VERSION

    def to_fields(self) -> dict:
        """The subset a finding carries, so a reader can audit the decision."""
        return {
            "pan_confidence": self.confidence,
            "pan_issuer": self.issuer,
            "pan_context_terms": list(self.context_terms),
            "pan_density": self.density,
            "pan_validator_version": self.validator_version,
            "luhn_valid": self.luhn_valid,
            "confidence_basis": self.basis,
        }


@dataclass(frozen=True, slots=True)
class PanHit:
    raw: str
    start: int
    end: int
    verdict: PanVerdict = field(compare=False)


def normalize_candidate(value: str) -> str:
    """Digits only, or "" when the run is not a plausible card shape.

    A card is written with ONE separator style. `4111 1111-1111 1111` is a
    concatenation of two different numbers far more often than it is a card, and
    accepting it is how a phone number joined to an extension became a PAN.
    """

    raw = str(value or "")
    if re.search(r"[A-Za-z*Xx]", raw):
        return ""
    separators = set(re.findall(r"[^\d]", raw))
    if len(separators) > 1:
        return ""
    digits = re.sub(r"[\s -]+", "", raw)
    if not re.fullmatch(r"\d{12,19}", digits):
        return ""
    if separators:
        groups = [len(part) for part in re.split(r"[\s -]+", raw.strip()) if part]
        # Real cards group in 4s (or 4-6-5 for Amex). A run grouped in 2s or 3s
        # is a date, a phone number or a serial.
        if any(size < 4 for size in groups[:-1]) or max(groups) > 7:
            return ""
    return digits


def card_issuer(digits: str) -> tuple[str, bool]:
    """(brand, whether this length is one that brand issues)."""

    pan = str(digits or "")
    for pattern, brand, lengths in _ISSUER_TABLE:
        if pattern.match(pan):
            return brand, len(pan) in lengths
    return "unknown", False


def is_luhn_valid(digits: str) -> bool:
    pan = str(digits or "")
    if not pan.isdigit():
        return False
    checksum = 0
    for index, char in enumerate(reversed(pan)):
        digit = int(char)
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def structural_exclusion(digits: str) -> str:
    """Why this Luhn-valid run cannot be a card, or ""."""

    body = digits[:-1]
    if len(set(digits)) == 1:
        return "every digit is the same"
    if len(set(body)) == 1:
        # 4444444444444448 is a serial number with a check digit on the end, and
        # it passes Luhn. No issuer allocates a range of one repeated digit.
        return "every digit but the last is the same"
    # A REPEATED short run - 1234567812345670, 4321432143214320 - is the shape
    # a placeholder or a generated test id actually takes. (A strictly ascending
    # run cannot be checked for here: base 10 has ten digits, so no 12-digit
    # number is one.)
    for period in range(1, 9):
        if len(body) > period and body == (body[:period] * (len(body) // period + 1))[:len(body)]:
            return f"the digits repeat a {period}-digit block"
    if len(digits) == 15 and digits[:2] in _IMEI_TAC_PREFIXES and card_issuer(digits)[0] != "amex":
        return "15 digits with an IMEI type-allocation prefix"
    return ""


def _word_stream(text: str) -> str:
    """Text reduced to space-separated words, padded at both ends.

    Two things depend on this. `card_number:` and `cardNumber` have to match the
    term "card number" - a label in a CSV header, a JSON key and a sentence are
    the same word. And "discard" must not match "card": comparing padded terms
    against a padded stream makes every match a whole-word one.
    """

    return " " + " ".join(re.split(r"[^a-z0-9]+", str(text or "").lower())) + " "


def _terms_in(window: str, terms: tuple[str, ...]) -> tuple[str, ...]:
    stream = _word_stream(window)
    return tuple(sorted({term for term in terms if f" {term} " in stream}))


def context_window(content: str, start: int, end: int, width: int = CONTEXT_WINDOW) -> str:
    return str(content or "")[max(0, start - width): end + width]


def validate_pan(
    raw: str,
    *,
    context: str = "",
    path_hint: str = "",
    density: int = 0,
) -> PanVerdict | None:
    """The one decision. None means "this is not a payment card number".

    Gate 1 shape      a single separator style, 12-19 digits, card-like grouping
    Gate 2 checksum   Luhn
    Gate 3 issuer     a real IIN prefix at a length that issuer uses
    Gate 4 exclusions repeated digits, counting sequences, IMEI shapes

    Confidence, and what each tier is allowed to claim downstream:
      HIGH    issuer-valid AND (a payment word nearby OR three distinct cards in
              the file). This is a card.
      MEDIUM  issuer-valid, nothing around it. Probably a card; worth a look.
      LOW     Luhn only, no recognised issuer, but payment words around it.
              Reported as a possible card and capped below CRITICAL.
      None    a Luhn-valid number with no issuer and no context - which is most
              of them.
    """

    digits = normalize_candidate(raw)
    if not digits:
        return None
    if not is_luhn_valid(digits):
        return None

    issuer, issuer_valid = card_issuer(digits)
    exclusion = structural_exclusion(digits)
    blob = f"{context} {path_hint}"
    positive = _terms_in(blob, POSITIVE_CONTEXT)
    negative = _terms_in(blob, NEGATIVE_CONTEXT)
    test_card = TEST_PAN_CATALOG.get(digits, "")

    if exclusion and not test_card:
        # Structure beats context: a document can say "card number" above a row
        # of repeated digits, and it is still not a card.
        return None

    if issuer_valid:
        if positive and not negative:
            confidence, basis = "HIGH", f"{issuer} prefix and length, with payment context nearby"
        elif positive and negative:
            confidence, basis = "MEDIUM", f"{issuer} prefix and length, but the surrounding text also names a non-card identifier"
        elif density >= 3:
            confidence, basis = "HIGH", f"{issuer} prefix and length, and {density} distinct card numbers in this file"
        elif negative:
            # An issuer-shaped number sitting under "IMEI" or "order number" is
            # the exact false positive this module exists to stop.
            return None
        else:
            confidence, basis = "MEDIUM", f"{issuer} prefix and length, no payment context nearby"
    else:
        if positive and not negative:
            confidence, basis = "LOW", "Luhn checksum and payment context, but no recognised card issuer"
        else:
            return None

    return PanVerdict(
        digits=digits,
        issuer=issuer,
        issuer_valid=issuer_valid,
        luhn_valid=True,
        confidence=confidence,
        context_terms=positive,
        negative_terms=negative,
        density=density,
        test_card=test_card,
        basis=basis,
    )


def _issued_card(raw: str) -> str:
    """The digits of `raw` when it is card-shaped, Luhn-valid, at a length its issuer
    uses and not a structural non-card - or ""."""

    digits = normalize_candidate(raw)
    if digits and is_luhn_valid(digits) and card_issuer(digits)[1] and not structural_exclusion(digits):
        return digits
    return ""


def card_windows(run: str) -> list[tuple[int, int]]:
    """(start, end) of the stretches of one candidate run to judge as cards.

    The candidate pattern takes the LONGEST run of digits and separators, so a card
    followed on its line by an expiry or a CVV - "4111 1111 1111 1111 05/27", "Card
    number 4111111111111111 123", a tab-separated row - arrives as one 18- or 19-digit
    run. That run failed the card-shape check whole and the card inside it was never
    tried, in all three detectors. A run that is an issued card as it stands is still
    judged as it stands. Otherwise it is cut into its digit groups and, from each group,
    the longest window of WHOLE groups that is an issued card is taken, left to right -
    the way the report-time mask (masking._card_spans) already reads a run. A run with
    no such window is judged whole, as before, so a number the validator would have
    accepted at LOW confidence still reaches it.
    """

    if _issued_card(run):
        return [(0, len(run))]
    groups = [(match.start(), match.end()) for match in _DIGIT_GROUP_RE.finditer(run)]
    windows: list[tuple[int, int]] = []
    first = 0
    while first < len(groups):
        found = None
        for last in range(len(groups) - 1, first - 1, -1):
            if _issued_card(run[groups[first][0]:groups[last][1]]):
                found = last
                break
        if found is None:
            first += 1
            continue
        windows.append((groups[first][0], groups[found][1]))
        first = found + 1
    return windows or [(0, len(run))]


def pan_hits(content: str, *, path_hint: str = "") -> list[PanHit]:
    """Every accepted card in a document, with the file's own density applied.

    Density is a two-pass property: how many DISTINCT issuer-valid cards the
    file holds decides whether a card with no words around it is confirmed. A
    payments export is a list of bare numbers and no prose, and that is the case
    a per-match context window can never see.
    """

    text = str(content or "")
    if not text:
        return []

    candidates = [
        (match.group(0)[start:end], match.start() + start, match.start() + end)
        for match in PAN_CANDIDATE_RE.finditer(text)
        for start, end in card_windows(match.group(0))
    ]
    if not candidates:
        return []

    distinct: set[str] = set()
    for raw, _start, _end in candidates:
        digits = _issued_card(raw)
        if digits:
            distinct.add(digits)
    density = len(distinct)

    hits: list[PanHit] = []
    for raw, start, end in candidates:
        verdict = validate_pan(
            raw,
            context=context_window(text, start, end),
            path_hint=path_hint,
            density=density,
        )
        if verdict is not None:
            hits.append(PanHit(raw=raw, start=start, end=end, verdict=verdict))
    return hits


_SEVERITY_ORDER = ("LOW", "MEDIUM", "HIGH", "CRITICAL")

# What confidence is allowed to claim. A number we are only guessing at can be
# worth reviewing; it can never be the thing that pages someone at 2am.
_CONFIDENCE_CEILING = {"HIGH": "CRITICAL", "MEDIUM": "HIGH", "LOW": "MEDIUM"}


def cap_severity(severity: str, confidence: str) -> str:
    """`severity` lowered to what `confidence` supports."""

    level = str(severity or "LOW").upper()
    ceiling = _CONFIDENCE_CEILING.get(str(confidence or "LOW").upper(), "MEDIUM")
    if level not in _SEVERITY_ORDER:
        return level
    return level if _SEVERITY_ORDER.index(level) <= _SEVERITY_ORDER.index(ceiling) else ceiling
