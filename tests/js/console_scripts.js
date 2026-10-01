// The console's scripts in the order index.html loads them - console/*.js, then app.js -
// so a render harness runs the same code a browser does (D4 split app.js by feature).
"use strict";

const fs = require("fs");
const path = require("path");

const FRONTEND = path.resolve(__dirname, "..", "..", "frontend");

function consoleScripts() {
  const index = fs.readFileSync(path.join(FRONTEND, "index.html"), "utf8");
  const names = [...index.matchAll(/<script src="\/static\/((?:console\/[\w.-]+)|app)\.js\?v=\d+"><\/script>/g)]
    .map((match) => `${match[1]}.js`);
  if (!names.includes("app.js")) throw new Error("index.html loads no app.js");
  return names.map((name) => path.join(FRONTEND, name));
}

// Run them into a vm context, one script each, as the browser would.
function runConsole(vm, context) {
  for (const file of consoleScripts()) {
    vm.runInContext(fs.readFileSync(file, "utf8"), context, { filename: path.relative(FRONTEND, file) });
  }
}

module.exports = { consoleScripts, runConsole };
