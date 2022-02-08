# Digital Covid Certificate - Austrian Rule Sets

The goal of this project is to maintain a set of covid certificate business
rule sets that are applicable in Austria.

Maintained sets:

* **TUGRAZ:** The rules for "TU Graz". [See details](./rulesets/TUGRAZ/README.md)
* **PLUS**: The rules for "Paris Lodron University of Salzburg". [See details](./rulesets/PLUS/README.md)
* **PHST**: The rules for "Pädagogische Hochschule Steiermark". [See details](./rulesets/PHST/README.md)

Mirrored sets:

* **AT-PROD:** https://dgc-trust.qr.gv.at/trustlist (only rules for AT)
* **AT-TEST:** https://dgc-trusttest.qr.gv.at/trustlist (only rules for AT)

The format of the specific rules follows the official EU-DCC standard as
described here:
https://github.com/eu-digital-green-certificates/dgc-business-rules-testdata

The format of the rule sets mirrors the CBOR decoded business rules as described
here: https://github.com/Federal-Ministry-of-Health-AT/green-pass-overview

Feel free contribute your own set.