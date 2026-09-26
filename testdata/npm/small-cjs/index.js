const chalk = require("chalk");
const dayjs = require("dayjs");
const _ = require("lodash");
const qs = require("qs");
const semver = require("semver");
const { v4: uuidv4 } = require("uuid");

module.exports = {
  banner: (text) => chalk.bold(text),
  stamp: () => dayjs("2026-01-01").format("YYYY-MM-DD"),
  pick: (obj, keys) => _.pick(obj, keys),
  query: (obj) => qs.stringify(obj),
  newer: (a, b) => semver.gt(a, b),
  id: () => uuidv4(),
};
