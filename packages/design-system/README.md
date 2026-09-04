# Stead design system foundation

This package supplies original Apache-2.0 Stead tokens and accessible primitives. The
foundation uses the approved product qualities—calm layered surfaces, compact controls,
stable layout, semantic color names, and restrained motion—without importing Devlane code,
assets, routes, or ontology.

The pinned Devlane record `DEP-APP-DEVLANE-SOURCE-7719DCAD` currently authorizes an inert
source reference only (`distributed_in: []`). Accordingly, these files contain no copied or
adapted Devlane source. A future import must first update the approval for the exact proposed
distribution, add file-level provenance and modification records, and retain the MIT notice.

`tokens.css` supports System, Light, and Dark behavior. Text and focus treatment remain
authoritative; semantic color is supplemental. `SecurityMarking` renders only supplied text
and marking kinds and contains no profile-ID behavior or authorization decision. Loading,
empty, and error states preserve region geometry and screen-reader status, and errors expose
only a safe correlation ID.
