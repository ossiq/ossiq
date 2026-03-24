// Sphinx 9 changed stopwords from Array to Set, but sphinx-immaterial still
// calls .indexOf() on it. Patch Set.prototype so both work.
if (typeof Set.prototype.indexOf === "undefined") {
  Set.prototype.indexOf = function (value) {
    return this.has(value) ? 0 : -1;
  };
}
