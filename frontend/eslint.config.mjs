// C7: the console's JavaScript may not use a name nobody defined. `node --check` finds
// syntax errors only; a renamed function or a deleted constant is a ReferenceError the
// first time a page runs that line - Phase A's Remediation outage was exactly that.
//
// Pinned: eslint and globals are exact versions in package.json, and CI runs this file
// through scripts/static_gate.py with the local install in node_modules (`npm run lint`
// does the same), never a global one. Each script is a classic <script> and needs nothing
// but the browser's globals; if one ever has to use another's, list that name here with
// the reason rather than switching the rule off.
import globals from "globals";

export default [
  {
    files: ["*.js"],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: "script",
      globals: { ...globals.browser },
    },
    rules: {
      "no-undef": "error",
    },
  },
];
