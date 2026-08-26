function parseFileUrl(pathname, index) {
  const code = pathname.codePointAt(index);
  if (code === 0x25 && pathname[index + 1] === "2") {
    throw new Error("Encoded path separator is not allowed");
  }
}

function isZeroWidthCodePoint(code) {
  return (
    (code >= 0xFE00 && code <= 0xFE0F) ||
    (code >= 0xE0100 && code <= 0xE01EF)
  );
}

function decodeUnrelatedInput(input) {
  return Buffer.from(input);
}

const runtimeMode = process.env.NODE_ENV;
