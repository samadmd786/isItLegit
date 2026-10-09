"""Brands that scammers impersonate most, and where each one really lives.

Each brand has:
- domains: the registrable domains the brand actually sends links from.
- mention: a regex that detects the brand being named in a message. These are
  deliberately conservative ("Apple ID", not "apple") so a grocery list does
  not trigger brand checks.
- verify: the one safe thing to do instead of clicking. Shown to the user
  verbatim, so it must never contain a link.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Brand:
    key: str
    name: str
    domains: frozenset[str]
    mention: re.Pattern[str]
    verify: str


def _b(key: str, name: str, domains: list[str], mention: str, verify: str, case: bool = False) -> Brand:
    flags = 0 if case else re.IGNORECASE
    return Brand(key, name, frozenset(domains), re.compile(mention, flags), verify)


BRANDS: list[Brand] = [
    _b("paypal", "PayPal", ["paypal.com", "paypal.me", "paypalobjects.com"],
       r"\bpay\s?pal\b", "Open the PayPal app or type paypal.com yourself and check your activity there."),
    _b("amazon", "Amazon", ["amazon.com", "amazon.co.uk", "amazon.in", "amazon.ca", "amazon.de", "amzn.com", "amzn.to", "a.co", "amazonaws.com"],
       r"\bamazon\b|\bprime\s+(membership|video|account)\b", "Open the Amazon app yourself and look under Your Orders."),
    _b("apple", "Apple", ["apple.com", "icloud.com", "me.com", "apple.news"],
       r"\bapple\s?(id|pay|support|account|care)\b|\bicloud\b|\bApple\b", "Go to Settings on your iPhone and tap your name. Apple will never text you a link to unlock your account."),
    _b("microsoft", "Microsoft", ["microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com", "office365.com", "windows.com", "xbox.com"],
       r"\bmicrosoft\b|\bwindows\s+(defender|security)\b|\boffice\s?365\b|\boutlook\b", "Microsoft never calls or emails to fix your computer. Close the message and do not call any number in it."),
    _b("google", "Google", ["google.com", "gmail.com", "youtube.com", "goo.gl", "g.co", "googlemail.com"],
       r"\bgoogle\b(?!\s+play)|\bgmail\b", "Open Gmail yourself and check Security under your Google Account."),
    _b("netflix", "Netflix", ["netflix.com"],
       r"\bnetflix\b", "Open the Netflix app yourself and check Account. If your payment really failed, it will say so there."),
    _b("usps", "USPS", ["usps.com", "usps.gov"],
       r"\bUSPS\b|\bpostal\s+service\b|\bpost\s+office\b", "USPS does not text links asking for fees. Type usps.com yourself and enter your tracking number there."),
    _b("ups", "UPS", ["ups.com"],
       r"\bUPS\b", "Type ups.com yourself and enter the tracking number from your order receipt.", case=True),
    _b("fedex", "FedEx", ["fedex.com"],
       r"\bfed\s?ex\b", "Type fedex.com yourself and enter the tracking number from your order receipt."),
    _b("dhl", "DHL", ["dhl.com", "dhl.de"],
       r"\bDHL\b", "Type dhl.com yourself and enter the tracking number from your order receipt."),
    _b("irs", "IRS", ["irs.gov"],
       r"\bIRS\b|\binternal\s+revenue\b|\btax\s+refund\b", "The IRS contacts people by paper mail first, never by text or email. Do not reply."),
    _b("ssa", "Social Security", ["ssa.gov", "socialsecurity.gov"],
       r"\bsocial\s+security\s+(administration|office|benefits?)\b|\bSSA\b", "Social Security will not threaten you or ask for payment. Call 1-800-772-1213 yourself if you are worried."),
    _b("medicare", "Medicare", ["medicare.gov", "cms.gov"],
       r"\bmedicare\b", "Call 1-800-MEDICARE yourself, using the number on your Medicare card."),
    _b("chase", "Chase", ["chase.com", "jpmorganchase.com", "jpmorgan.com"],
       r"\bChase\b(?!\s+(after|down|away))", "Call the number on the back of your Chase card, or open the Chase app yourself.", case=True),
    _b("wellsfargo", "Wells Fargo", ["wellsfargo.com", "wf.com"],
       r"\bwells\s?fargo\b", "Call the number on the back of your Wells Fargo card, or open the app yourself."),
    _b("bofa", "Bank of America", ["bankofamerica.com", "bofa.com", "ml.com"],
       r"\bbank\s+of\s+america\b|\bBofA\b", "Call the number on the back of your Bank of America card, or open the app yourself."),
    _b("venmo", "Venmo", ["venmo.com"],
       r"\bvenmo\b", "Open the Venmo app yourself. Never send money back to someone who 'sent it by mistake'."),
    _b("zelle", "Zelle", ["zellepay.com", "zelle.com"],
       r"\bzelle\b", "Zelle payments cannot be undone. Call your bank using the number on your card before sending anything."),
    _b("coinbase", "Coinbase", ["coinbase.com"],
       r"\bcoinbase\b", "Open the Coinbase app yourself. Coinbase will never ask you to move coins to a 'safe' wallet."),
    _b("facebook", "Facebook", ["facebook.com", "fb.com", "facebookmail.com", "meta.com", "fb.me"],
       r"\bfacebook\b|\bmeta\s+(support|business)\b", "Open the Facebook app yourself and check Settings, then Security."),
    _b("instagram", "Instagram", ["instagram.com"],
       r"\binstagram\b", "Open the Instagram app yourself and check Settings, then Security."),
    _b("whatsapp", "WhatsApp", ["whatsapp.com", "whatsapp.net", "wa.me"],
       r"\bwhats\s?app\b", "WhatsApp will never ask for your 6-digit code. Do not share it with anyone."),
    _b("walmart", "Walmart", ["walmart.com"],
       r"\bwalmart\b", "Open the Walmart app yourself. Walmart does not give away gift cards for surveys."),
    _b("costco", "Costco", ["costco.com"],
       r"\bcostco\b", "Open the Costco app yourself. Costco does not give away prizes by text."),
    _b("att", "AT&T", ["att.com", "att.net"],
       r"\bAT&T\b|\bATT\b", "Open the myAT&T app yourself or call 611 from your phone.", case=True),
    _b("verizon", "Verizon", ["verizon.com", "vzw.com", "verizonwireless.com"],
       r"\bverizon\b", "Open the My Verizon app yourself or call 611 from your phone."),
    _b("xfinity", "Xfinity", ["xfinity.com", "comcast.com", "comcast.net"],
       r"\bxfinity\b|\bcomcast\b", "Open the Xfinity app yourself and check your bill there."),
    _b("docusign", "DocuSign", ["docusign.com", "docusign.net"],
       r"\bdocu\s?sign\b", "If you are not expecting a document, ask the sender by phone before opening it."),
    _b("ebay", "eBay", ["ebay.com"],
       r"\bebay\b", "Open the eBay app yourself and check Messages there."),
    _b("ezpass", "E-ZPass / toll agency", ["e-zpassny.com", "ezpassnj.com", "ezdrivema.com", "ezpassva.com", "sunpass.com", "bayareafastrak.org", "thetollroads.com", "txtag.org", "ntta.org", "ezpassmd.com", "ezpassde.com", "ezpassih.com", "illinoistollway.com", "getipass.com"],
       r"\be-?z\s?pass\b|\bsun\s?pass\b|\bfas\s?trak\b|\btoll\s+(services?|authority|agency)\b|\bi-?pass\b", "Toll agencies do not text links for unpaid tolls. Log in to your toll account yourself, from a bookmark or the app."),
]

BRANDS_BY_KEY = {b.key: b for b in BRANDS}

# Every official domain, so "is this link one of the real ones" is one lookup.
OFFICIAL_DOMAINS: dict[str, str] = {d: b.key for b in BRANDS for d in b.domains}

# Brand names as they appear inside domains. Used two ways:
#  - a domain token equal to (or, for long names, starting with) one of these
#    on a domain the brand does not own is impersonation: amazon-refunds.com.
#  - a domain label that is a near-miss of one is a lookalike: paypa1.com.
# Curated by hand rather than derived from BRANDS.domains, so generic words
# like "live", "office" and "outlook" never count as brand names.
BRAND_TOKENS: dict[str, str] = {
    "paypal": "paypal", "amazon": "amazon", "apple": "apple", "appleid": "apple",
    "icloud": "apple", "microsoft": "microsoft", "office365": "microsoft",
    "google": "google", "gmail": "google", "netflix": "netflix", "usps": "usps",
    "ups": "ups", "fedex": "fedex", "dhl": "dhl", "irs": "irs", "chase": "chase",
    "wellsfargo": "wellsfargo", "bankofamerica": "bofa", "bofa": "bofa",
    "venmo": "venmo", "zelle": "zelle", "coinbase": "coinbase",
    "facebook": "facebook", "instagram": "instagram", "whatsapp": "whatsapp",
    "walmart": "walmart", "costco": "costco", "verizon": "verizon",
    "xfinity": "xfinity", "comcast": "xfinity", "docusign": "docusign",
    "ebay": "ebay", "ezpass": "ezpass", "sunpass": "ezpass", "fastrak": "ezpass",
    "medicare": "medicare", "socialsecurity": "ssa", "ssa": "ssa", "att": "att",
}
