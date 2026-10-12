# Enterprise DSPM UI Redesign v2

This package includes a full frontend product polish pass for the DSPM console.

## Main improvements

- Rebuilt sidebar information architecture into product groups:
  - Command Center
  - Discovery
  - Governance
- Added executive Dashboard hero with posture score, live KPIs and quick actions.
- Added enterprise Scan Wizard flow above the existing scan form.
- Added Findings triage board and filter chips.
- Added MSSP customer portfolio hero for admin/customer management.
- Improved visual system:
  - modern gradients
  - glass-style topbar
  - premium cards
  - stronger spacing and typography
  - improved buttons, inputs, tables and drawer
  - responsive layout
  - dark mode compatibility
- Added dynamic posture score helper connected to existing Critical/High/Medium/Low/Total counters.
- Preserved existing backend API integration and existing HTML element IDs used by app.js.

## Changed files

- frontend/index.html
- frontend/styles.css
- frontend/app.js

## How to run

Use the same run method as the original project. The redesign does not require new Python packages.
