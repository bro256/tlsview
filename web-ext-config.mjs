// Files left out of the packaged extension (.xpi).
// web-ext already skips node_modules and dotfiles.
export default {
  ignoreFiles: [
    "package.json",
    "package-lock.json",
    "web-ext-config.mjs",
    "test",
    "TESTING.md",
  ],
};
