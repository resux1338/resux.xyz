// Wraps each code block in the writeups with a header showing the
// language and a copy button. Without JS the blocks still render fine.
(function () {
  "use strict";

  var COPY_ICON = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';

  // Zola reports the highlighter's grammar name, not what was written after the backticks
  var LANG_NAMES = { shellscript: "bash", plain: "text" };

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

    var wrap = document.createElement("figure");
    wrap.className = "codeblock";

    var head = document.createElement("figcaption");
    head.className = "codeblock-head";

    var label = document.createElement("span");
    label.textContent = LANG_NAMES[lang] || lang || "text";

    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "copy";
    btn.innerHTML = COPY_ICON + '<span class="copy-label">copy</span>';
    btn.setAttribute("aria-label", "Copy code to clipboard");

    var timer;
    btn.addEventListener("click", function () {
      var labelEl = btn.querySelector(".copy-label");
      copy(codeText(code)).then(function () {
        btn.dataset.state = "done";
        labelEl.textContent = "copied";
      }, function () {
        labelEl.textContent = "failed";
      }).then(function () {
        clearTimeout(timer);
        timer = setTimeout(function () {
          delete btn.dataset.state;
          labelEl.textContent = "copy";
        }, 1600);
      });
    });

    head.appendChild(label);
    head.appendChild(btn);
    pre.parentNode.insertBefore(wrap, pre);
    wrap.appendChild(head);
    wrap.appendChild(pre);
  });
})();
