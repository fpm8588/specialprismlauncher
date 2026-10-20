"use strict";

// Download buttons are ordinary links: clicking one makes the browser GET the file, and GitHub answers with
// "Content-Disposition: attachment", so the file is saved and the visitor stays on this page. This script only
// adds feedback and a hint about which download suits the visitor's computer.

(function () {
  var statusBox = document.getElementById("dl-status");

  function say(text) {
    if (!statusBox) return;
    statusBox.textContent = text;
    statusBox.hidden = false;
  }

  document.querySelectorAll("a[data-name]").forEach(function (link) {
    link.addEventListener("click", function () {
      say("Downloading " + link.dataset.name + ". It will appear in your Downloads folder. If nothing happens, right-click the button and choose “Save Link As”.");
    });
  });

  // Which computer is this? navigator.platform is deprecated but still widely filled in; fall back to the user agent.
  var platform = ((navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || navigator.userAgent || "").toLowerCase();
  var isMac = platform.indexOf("mac") !== -1;
  var isWindows = platform.indexOf("win") !== -1;
  var note = document.getElementById("os-note");

  if (isMac) {
    var card = document.getElementById("card-mac");
    var badge = document.getElementById("badge-mac");
    if (card) card.classList.add("highlight");
    if (badge) badge.hidden = false;
  } else if (note && isWindows) {
    note.textContent = "You're on Windows. The launcher app is for Mac (Apple silicon) only for now. The Windows download is the relay server, for hosting your own relay.";
    note.hidden = false;
  } else if (note) {
    note.textContent = "The launcher app is for Mac (Apple silicon) only for now.";
    note.hidden = false;
  }

  // Copy buttons.
  document.querySelectorAll("button[data-copy]").forEach(function (button) {
    button.addEventListener("click", function () {
      var source = document.getElementById(button.dataset.copy);
      if (!source) return;
      var text = source.textContent.trim();
      var done = function () {
        var old = button.textContent;
        button.textContent = "Copied";
        setTimeout(function () { button.textContent = old; }, 1800);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, function () { fallback(text, done); });
      } else {
        fallback(text, done);
      }
    });
  });

  function fallback(text, done) {
    var box = document.createElement("textarea");
    box.value = text;
    box.setAttribute("readonly", "");
    box.style.position = "fixed";
    box.style.opacity = "0";
    document.body.appendChild(box);
    box.select();
    try { document.execCommand("copy"); done(); } catch (e) { /* nothing more to try */ }
    document.body.removeChild(box);
  }
})();
