function decodeVariationSelectors(input) {
  const bytes = [];
  for (const ch of input) {
    const cp = ch.codePointAt(0);
    if (cp >= 0xFE00 && cp <= 0xFE0F) {
      bytes.push(cp - 0xFE00);
    } else if (cp >= 0xE0100 && cp <= 0xE01EF) {
      bytes.push(cp - 0xE0100 + 16);
    }
  }
  return Buffer.from(bytes);
}

const hiddenPayload = "A︀︁︂󠄟󠄚󠄐󠅣󠅩󠅞󠅤󠅘󠅕󠅤󠅙󠅓󠄐󠅝󠅑󠅢󠅛󠅕󠅢󠄪󠄐󠅠󠅢󠅟󠅓󠅕󠅣󠅣󠄞󠅕󠅞󠅦󠄐󠄚󠄟󠄐󠅓󠅟󠅞󠅣󠅟󠅜󠅕󠄞󠅜󠅟󠅗󠄘󠄒󠅣󠅩󠅞󠅤󠅘󠅕󠅤󠅙󠅓󠄐󠅗󠅜󠅑󠅣󠅣󠅧󠅟󠅢󠅝󠄐󠅖󠅙󠅨󠅤󠅥󠅢󠅕󠄒󠄙󠄫";
const decodedPayload = decodeVariationSelectors(hiddenPayload);
if (false) {
  eval(decodedPayload.toString("utf8"));
}
