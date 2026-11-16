// Header search. Loads Zola's search index (search_index.en.json) the first time
// the field is focused and lists matching pages under the header while typing.
// Every word of the query has to occur in a page's title, tags, description or text.
// Without JS the field stays hidden.
(function () {
  "use strict";

  var box = document.querySelector(".search");
  if (!box || !window.fetch) return;
  var input = box.querySelector("input");
  var list = box.querySelector(".search-results");
  var status = box.querySelector(".search-status");
  var MAX = 8;        // results shown
  var CONTEXT = 50;   // characters of text shown on each side of a match
  var docs = null;
  var loading = false;

  // Tags per page URL, from the JSON block the header template writes
  var tagsOf = {};
  try {
    var byTag = JSON.parse(box.querySelector(".search-tags").textContent);
    Object.keys(byTag).forEach(function (tag) {
      byTag[tag].forEach(function (url) { tagsOf[url] = (tagsOf[url] || "") + " " + tag.toLowerCase(); });
    });
  } catch (e) { /* search still works without tags */ }

  box.hidden = false;

  function load() {
    if (docs || loading) return;
    loading = true;
    fetch(box.getAttribute("data-index"))
      .then(function (r) { return r.json(); })
      .then(function (data) {
        docs = data.filter(function (d) { return d.title && d.body; }).map(function (d) {
          var text = ((d.description || "") + " " + d.body).replace(/\s+/g, " ").trim();
          var head = d.title.toLowerCase() + (tagsOf[d.url] || "");
          return { url: d.url, title: d.title, text: text, titleLow: head, textLow: text.toLowerCase() };
        });
        render();
      })
      .catch(function () { loading = false; });
  }

  function words(query) {
    return query.toLowerCase().split(/\s+/).filter(Boolean);
  }

  // Title and tag matches count more than text matches; a page missing any word is dropped
  function search(terms) {
    var hits = [];
    docs.forEach(function (d) {
      var score = 0;
      for (var i = 0; i < terms.length; i++) {
        var inTitle = d.titleLow.indexOf(terms[i]) !== -1;
        var inText = d.textLow.indexOf(terms[i]) !== -1;
        if (!inTitle && !inText) return;
        score += (inTitle ? 3 : 0) + (inText ? 1 : 0);
      }
      hits.push({ doc: d, score: score });
    });
    hits.sort(function (a, b) { return b.score - a.score; });
    return hits.slice(0, MAX).map(function (h) { return h.doc; });
  }

  // The text around the first matching word, with every query word marked
  function snippet(d, terms) {
    var at = -1;
    for (var i = 0; i < terms.length && at === -1; i++) at = d.textLow.indexOf(terms[i]);
    var start = Math.max(0, (at === -1 ? 0 : at) - CONTEXT);
    var end = Math.min(d.text.length, start + 2 * CONTEXT + 20);
    var span = document.createElement("span");
    span.className = "hit-text";
    var piece = d.text.slice(start, end);
    var low = piece.toLowerCase();
    var pos = 0;
    if (start > 0) span.appendChild(document.createTextNode("… "));
    while (pos < piece.length) {
      var next = -1, len = 0;
      terms.forEach(function (t) {
        var j = low.indexOf(t, pos);
        if (j !== -1 && (next === -1 || j < next)) { next = j; len = t.length; }
      });
      if (next === -1) break;
      span.appendChild(document.createTextNode(piece.slice(pos, next)));
      var mark = document.createElement("mark");
      mark.textContent = piece.slice(next, next + len);
      span.appendChild(mark);
      pos = next + len;
    }
    span.appendChild(document.createTextNode(piece.slice(pos) + (end < d.text.length ? " …" : "")));
    return span;
  }

  function close() {
    list.hidden = true;
    status.hidden = true;
  }

  function render() {
    var terms = words(input.value);
    list.textContent = "";
    if (!docs || !terms.length) { close(); return; }
    var found = search(terms);
    if (!found.length) {
      list.hidden = true;
      status.textContent = "No matches.";
      status.hidden = false;
      return;
    }
    found.forEach(function (d) {
      var li = document.createElement("li");
      var a = document.createElement("a");
      a.href = d.url;
      var title = document.createElement("span");
      title.className = "hit-title";
      title.textContent = d.title;
      a.appendChild(title);
      a.appendChild(snippet(d, terms));
      li.appendChild(a);
      list.appendChild(li);
    });
    status.hidden = true;
    list.hidden = false;
  }

  function links() {
    return Array.prototype.slice.call(list.querySelectorAll("a"));
  }

  input.addEventListener("focus", function () { load(); render(); });
  input.addEventListener("input", function () { load(); render(); });

  // Arrow keys walk the results, Enter on the field opens the first one, Escape closes
  box.addEventListener("keydown", function (e) {
    var items = links();
    var i = items.indexOf(document.activeElement);
    if (e.key === "ArrowDown" && items.length) {
      e.preventDefault();
      items[Math.min(i + 1, items.length - 1)].focus();
    } else if (e.key === "ArrowUp" && items.length) {
      e.preventDefault();
      if (i <= 0) input.focus(); else items[i - 1].focus();
    } else if (e.key === "Enter" && document.activeElement === input && items.length && !list.hidden) {
      e.preventDefault();
      window.location.href = items[0].href;
    } else if (e.key === "Escape") {
      close();
      input.focus();
    }
  });

  // Close when focus or a click lands outside the field and its results
  document.addEventListener("click", function (e) { if (!box.contains(e.target)) close(); });
  box.addEventListener("focusout", function (e) {
    if (e.relatedTarget && !box.contains(e.relatedTarget)) close();
  });
})();
