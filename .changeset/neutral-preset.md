---
'@sokpheak/sp-jwt-auth': patch
---

Public-repo hygiene release. The second built-in preset is now `presets.spSaas` (a neutral name for the `{ success, data }` envelope host with second factor, company switch and account routes); if you used the previous second preset, switch to `presets.spSaas`, the routes and behaviour are the same. Adds a CI check against client names in a public repo and a gitleaks secret scan before every release. No runtime change otherwise.
