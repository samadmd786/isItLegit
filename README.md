# Is This Legit? 🛡️

A scam checker built for your parents. Paste a text or email you're not sure
about and get a verdict first, **DON'T CLICK / BE CAREFUL / LOOKS OK**,
then one plain sentence on why and one safe thing to do instead. In eight
languages, with a button that reads the answer out loud.

Built for the AWS Builder Center weekend challenge: *build an agent people
actually enjoy using* (`#agents`).

**Live demo:** _(added after deploy)_

![A fake PayPal email gets DON'T CLICK](docs/screenshots/01-paypal-scam.jpg)

## How it works

Rules decide, AI explains.

```
Browser (Amplify Hosting, static HTML/JS)
   │  POST {message, language}
   ▼
API Gateway HTTP API (throttled: 5 req/s)
   ▼
AWS Lambda
   ├─ Layer 1  backend/checks.py   deterministic checks → verdict
   │           lookalike domains (paypa1, rnicrosoft, xn--), brand names in
   │           someone else's domain, shorteners, risky TLDs, IP links,
   │           urgency, gift-card/crypto asks, code requests, "Hi Mom new
   │           number", fake tech support, SPF/DKIM/DMARC + From/Reply-To
   │           mismatches when headers are pasted
   └─ Layer 2  backend/explain.py  Amazon Bedrock (Nova Micro) → words
               writes the headline, the why and the what-to-do at a 6th-grade
               reading level, in the reader's language
```

Why split it this way:

- **A scam message can't talk its way to a green light.** The verdict comes
  from Layer 1. The model only explains it. If the model's English output
  calls a flagged message safe, it's discarded and a template is used. The
  pasted message is fenced off as untrusted input in the prompt.
- **It never opens a link.** Everything is decided from the text. Domains are
  shown defanged (`evil[.]com`), and the AI's output is defanged too, so
  the explainer can never become the thing someone clicks.
- **It degrades instead of failing.** If Bedrock is throttled, the same
  verdict comes back with a rule-written explanation.
- **Nothing is stored.** The Lambda logs rule ids and timings, never message
  text.

## Measured

| What | Result |
| --- | --- |
| **Held-out messages** (`samples/holdout*.json`, written after the rules were frozen, 20 scams + 12 real, first run) | 16/20 scams flagged; 0/12 real messages got DON'T CLICK; 1 store promo got BE CAREFUL |
| Same held-out sets after adding rules for the 4 misses | 20/20 flagged (tuned, so not a fair number; kept as regression tests) |
| Build corpus (`samples/corpus.json`, 17 scams + 10 real) | 27/27 verdicts. Written while building the rules, so this is a regression suite, not a benchmark |
| AI answers that passed validation (live, Nova Micro) | 28/28, including a prompt-injection attempt |
| Reading level of the explanation (Flesch-Kincaid, English) | median grade 3.1, max 5.2 |
| Latency | median 0.7 s per check |

The four first-run misses were all link-free scams: an "I sent you money by
mistake" refund trick, a fake job offer, a "wrong number" opener, and a fake
bank fraud-department text.

Reproduce:

```bash
python3 -m venv .venv && .venv/bin/pip install pytest boto3
.venv/bin/python -m pytest -q                               # 83 offline tests
.venv/bin/python scripts/scan.py                            # build corpus
.venv/bin/python scripts/scan.py --holdout                  # held-out round 1
.venv/bin/python scripts/scan.py --holdout2                 # held-out round 2
AWS_PROFILE=<bedrock-profile> .venv/bin/python scripts/live_check.py   # live Bedrock
```

## Run locally

```bash
AWS_PROFILE=<bedrock-profile> .venv/bin/python scripts/dev_server.py
# open http://localhost:8010
```

Without AWS credentials it still works, using the rule-written explanation.

## Deploy

```bash
scripts/deploy.sh --profile <deployer-profile>     # CloudFormation + Amplify
scripts/destroy.sh --profile <deployer-profile>    # remove everything
```

Requires Bedrock model access to Amazon Nova Micro in `us-east-1`.

## Languages

English, Spanish, Chinese, Hindi, Vietnamese, Korean, Tagalog, Portuguese.
Bengali, Urdu and Arabic were tested and left out: Nova Micro produced wrong
words and mixed scripts. They need a larger model.

## Limits

This is a helper, not a guarantee. It can't see where a link really goes,
and a well-crafted message that uses the real company's domain will look OK.
The safe-action advice is the backstop: go to the app or the number on your
card yourself.
