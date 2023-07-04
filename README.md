# Digital Covid Certificate - Austrian Rule Sets

The goal of this project is to maintain a set of covid certificate business
rule sets that are applicable in Austria.

**Note:** This project depends on the DCC infrastructure of the Austrian
Government. Since the DCC infrastructure is [no longer available since June
2023](https://github.com/Federal-Ministry-of-Health-AT/green-pass-overview/issues/11#issuecomment-1617997232),
this project is no longer actively maintained.

Maintained sets:

* **TUGRAZ:** The rules for "TU Graz". [See details](./rulesets/TUGRAZ/README.md)
* **PLUS**: The rules for "Paris Lodron University of Salzburg". [See details](./rulesets/PLUS/README.md)
* **PHST**: The rules for "Pädagogische Hochschule Steiermark". [See details](./rulesets/PHST/README.md)

Mirrored sets:

* **AT-PROD:** https://dgc-trust.qr.gv.at/trustlist (only CERTLOGIC rules for AT)
* **AT-TEST:** https://dgc-trusttest.qr.gv.at/trustlist (only CERTLOGIC rules for AT)

The format of the specific rules follows the official EU-DCC standard as
described here:
https://github.com/eu-digital-green-certificates/dgc-business-rules-testdata

The format of the rule sets mirrors the CBOR decoded business rules as described
here: https://github.com/Federal-Ministry-of-Health-AT/green-pass-overview

Feel free contribute your own set.

## Further resources

* Currently active rules in text form: https://corona-ampel.gv.at/aktuelle-massnahmen/bundesweite-massnahmen/

## Tools

```bash
poetry install
# To import the current AT-PROD/AT-TEST rules
poetry run ./make.py import-at
# To reformat/sort all rules (so diffs are simpler)
poetry run ./make.py format
# Build the web directory served via GitHub Pages
poetry run ./make.py build <somedir>
```
