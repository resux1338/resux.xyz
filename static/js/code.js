// Adds a "Copy" button to command blocks in the writeups: fenced blocks with
// a language other than plain text. Output blocks get no button.
// Also adds the "Top" button that appears after scrolling down.
// Without JS the blocks still render fine and there is simply no button.
(function () {
  "use strict";

  // data-lang values Zola emits for blocks that are not commands
  var PLAIN = { "": true, plain: true, text: true, txt: true };

  // Plain text of a block: one entry per rendered line, line numbers dropped
  function codeText(code) {
    var clone = code.cloneNode(true);
    clone.querySelectorAll(".giallo-ln").forEach(function (n) { n.remove(); });
    var lines = clone.querySelectorAll(".giallo-l");
    if (lines.length) {
      return Array.prototype.map.call(lines, function (l) {
        return l.textContent.replace(/\n$/, "");
      }).join("\n");
    }
    return clone.textContent.replace(/\n$/, "");
  }

  function copy(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }
    // Fallback for plain http (e.g. zola serve on a LAN address)
    return new Promise(function (resolve, reject) {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy") ? resolve() : reject(); }
      catch (e) { reject(e); }
      finally { ta.remove(); }
    });
  }

  document.querySelectorAll(".prose pre").forEach(function (pre) {
    var code = pre.querySelector("code") || pre;
    var lang = code.getAttribute("data-lang") || pre.getAttribute("data-lang") || "";
    if (PLAIN[lang.toLowerCase()]) return;

    var wrap = document.createElement("div");
    wrap.className = "codeblock";

    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "copy";
    btn.textContent = "Copy";
    btn.setAttribute("aria-label", "Copy code to clipboard");

    var timer;
    btn.addEventListener("click", function () {
      copy(codeText(code)).then(function () {
        btn.textContent = "Copied";
      }, function () {
        btn.textContent = "Failed";
      }).then(function () {
        clearTimeout(timer);
        timer = setTimeout(function () { btn.textContent = "Copy"; }, 1600);
      });
    });

    pre.parentNode.insertBefore(wrap, pre);
    wrap.appendChild(btn);
    wrap.appendChild(pre);
  });

  // "Top" button: hidden until the page is scrolled one screen down
  var top = document.createElement("button");
  top.type = "button";
  top.className = "to-top";
  top.textContent = "\u2191 Top";
  top.setAttribute("aria-label", "Back to top");
  top.hidden = true;
  document.body.appendChild(top);

  function toggle() {
    var show = window.scrollY > window.innerHeight;
    if (top.hidden === show) top.hidden = !show;
  }
  window.addEventListener("scroll", toggle, { passive: true });
  window.addEventListener("resize", toggle);
  toggle();

  top.addEventListener("click", function () {
    window.scrollTo(0, 0);
    // the button hides itself now, so hand keyboard focus to the start of the page
    var header = document.querySelector(".site-header");
    if (header) {
      header.setAttribute("tabindex", "-1");
      header.focus({ preventScroll: true });
    }
  });
})();
