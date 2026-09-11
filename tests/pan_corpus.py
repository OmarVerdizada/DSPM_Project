"""A deterministic corpus for measuring the payment-card detector.

Generated rather than checked in: a seeded generator is reviewable in a way a
300 KB blob of card-shaped numbers is not, and it makes the SHAPE of each case
explicit - which is the thing under test.

Every "card" here is synthetic. The body digits come from a fixed seed and the
check digit is computed, so the numbers satisfy Luhn and carry a real issuer
prefix without being anyone's card.

Three populations:

  positive  a real-format card in the kind of text one actually appears in -
            a payment record, a CSV export, a JSON payload, a gateway log.
  negative  a Luhn-valid number that is NOT a card. These are the shapes that
            actually occur: IMEIs, order and tracking ids, loyalty numbers,
            meter readings. A checksum alone cannot tell them apart from a
            card, which is the whole point.
  clean     ordinary business prose, including long digit runs that fail Luhn.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

# (issuer prefix, total length). Real IIN ranges, synthetic bodies.
_BRANDS = (
    ("4", 16), ("4", 13), ("4", 19),
    ("51", 16), ("52", 16), ("53", 16), ("54", 16), ("55", 16),
    ("2221", 16), ("2720", 16),
    ("34", 15), ("37", 15),
    ("6011", 16), ("65", 16), ("644", 16),
    ("3528", 16), ("3589", 16),
    ("62", 16), ("62", 19),
    ("300", 14), ("36", 14), ("38", 16),
)

# Luhn-valid but not a card: the prefix is outside every issuer range, or the
# length is one no issuer at that prefix uses.
_NON_CARD_SHAPES = (
    ("35", 15),    # IMEI type-allocation code
    ("86", 15),    # IMEI, Chinese TAC
    ("49", 15),    # IMEI
    ("99", 14),    # internal order id
    ("70", 17),    # tracking number
    ("80", 18),    # consignment
    ("10", 12),    # meter reading
    ("77", 13),    # loyalty number
    ("91", 17),    # warehouse id
    ("88", 14),    # ticket number
)

_POSITIVE_TEMPLATES = (
    "Payment record {i}\nCardholder: {name}\nCard number: {pan}\nExpiry: {mm}/{yy}\nCVV: {cvv}\n",
    "card_number,expiry,cvv,amount\n{pan},{mm}/{yy},{cvv},{amount}.00\n",
    '{{"cardNumber":"{pan}","expiryMonth":"{mm}","expiryYear":"20{yy}","cvv":"{cvv}"}}',
    "{ts} gateway=stripe action=authorize card={pan} exp={mm}/{yy} amount={amount} result=approved",
    "Refund request for the debit card ending {last4}. Full PAN on file: {pan}. Merchant reference {i}.",
    "Please charge the credit card {pan} (expires {mm}/{yy}) for invoice {i}.",
)

# Positives with NO payment word anywhere: a payments export is a column of bare
# numbers. Density is the only thing that can confirm these.
_DENSE_TEMPLATE = "{a}\n{b}\n{c}\n{d}\n"

_NEGATIVE_TEMPLATES = (
    "Device IMEI: {num} registered to the mobile fleet on {ts}.",
    "asset_tag,serial number,location\nAT-{i},{num},Floor {i}\n",
    "Order number {num} shipped on {ts}; tracking number to follow.",
    "Loyalty membership {num} was redeemed at store {i}.",
    "Meter number {num} read at {ts}; consumption within range.",
    "Support ticket number {num} was closed by the service desk.",
    "Consignment {num} cleared customs on {ts}.",
    "Warehouse reference number {num} assigned to pallet {i}.",
)

_CLEAN_TEMPLATES = (
    "The quarterly business review is scheduled for {ts} in meeting room {i}.",
    "Server uptime for host {i} was 99.98% over the reporting period.",
    "Minutes of the {i}th operations meeting: attendance {i}, apologies 2.",
    "Invoice total {amount}.00 EUR, net {amount} plus tax, due in 30 days.",
    "Build {i} completed in {i} seconds with {i} warnings and no errors.",
    "Employee headcount rose to {i} across {i} offices during the period.",
    "Reference {bad} was logged against change request CR-{i}.",
    "Temperature readings: {i}.4, {i}.9, {i}.2 degrees over three days.",
)

_NAMES = ("Jane Doe", "Amir Karimov", "Leyla Aliyeva", "Tom Becker", "Sara Ng", "Rui Costa")


def _luhn_check_digit(body: str) -> str:
    total = 0
    for index, char in enumerate(reversed(body)):
        digit = int(char)
        if index % 2 == 0:  # the check digit will sit at index 0, so body shifts
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return str((10 - total % 10) % 10)


def _make_number(rng: random.Random, prefix: str, length: int) -> str:
    body = prefix + "".join(str(rng.randint(0, 9)) for _ in range(length - len(prefix) - 1))
    return body + _luhn_check_digit(body)


def _break_luhn(number: str) -> str:
    """The same number with a check digit that does NOT satisfy Luhn."""
    last = int(number[-1])
    return number[:-1] + str((last + 1) % 10)


@dataclass(frozen=True, slots=True)
class CorpusDocument:
    name: str
    text: str
    label: str  # "positive" | "negative" | "clean"
    pans: tuple[str, ...]


def build_corpus(seed: int = 20260910) -> list[CorpusDocument]:
    """150 positives, 150 hard negatives, 200 clean. Deterministic."""

    rng = random.Random(seed)
    documents: list[CorpusDocument] = []

    for index in range(150):
        prefix, length = _BRANDS[index % len(_BRANDS)]
        pan = _make_number(rng, prefix, length)
        if index % 10 == 0:
            # A bare export: four cards, no payment word anywhere in the file.
            others = [_make_number(rng, *_BRANDS[(index + offset) % len(_BRANDS)]) for offset in (1, 2, 3)]
            text = _DENSE_TEMPLATE.format(a=pan, b=others[0], c=others[1], d=others[2])
            pans = (pan, *others)
        else:
            template = _POSITIVE_TEMPLATES[index % len(_POSITIVE_TEMPLATES)]
            text = template.format(
                i=1000 + index,
                pan=pan if index % 3 else " ".join(pan[pos:pos + 4] for pos in range(0, len(pan), 4)),
                name=_NAMES[index % len(_NAMES)],
                mm=f"{rng.randint(1, 12):02d}",
                yy=f"{rng.randint(26, 31)}",
                cvv=f"{rng.randint(100, 999)}",
                amount=rng.randint(10, 9000),
                ts=f"2026-0{rng.randint(1, 9)}-1{rng.randint(0, 9)}T09:{index % 60:02d}:00Z",
                last4=pan[-4:],
            )
            pans = (pan,)
        documents.append(CorpusDocument(f"positive_{index:03d}.txt", text, "positive", pans))

    for index in range(150):
        prefix, length = _NON_CARD_SHAPES[index % len(_NON_CARD_SHAPES)]
        number = _make_number(rng, prefix, length)
        template = _NEGATIVE_TEMPLATES[index % len(_NEGATIVE_TEMPLATES)]
        text = template.format(
            num=number,
            i=2000 + index,
            ts=f"2026-0{rng.randint(1, 9)}-2{rng.randint(0, 8)}",
        )
        if index % 5 == 0:
            # A slice with NO identifying word at all - just the bare number in
            # neutral prose. Nothing but its shape can rule it out.
            text = f"Record {2000 + index}: {number} logged by the nightly job.\n"
        documents.append(CorpusDocument(f"negative_{index:03d}.txt", text, "negative", ()))

    for index in range(200):
        template = _CLEAN_TEMPLATES[index % len(_CLEAN_TEMPLATES)]
        text = template.format(
            i=3000 + index,
            amount=rng.randint(100, 99000),
            ts=f"2026-1{rng.randint(0, 2)}-0{rng.randint(1, 9)}",
            bad=_break_luhn(_make_number(rng, "4", 16)),
        )
        documents.append(CorpusDocument(f"clean_{index:03d}.txt", text, "clean", ()))

    return documents
