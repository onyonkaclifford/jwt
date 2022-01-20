export function encode(data) {
  let base64String = Buffer.from(JSON.stringify(data), "binary").toString(
    "base64"
  );

  while (base64String.endsWith("=")) {
    base64String = base64String.slice(0, -1);
  }

  return encodeURIComponent(base64String);
}

export function decode(data) {
  let dataToDecode = decodeURIComponent(data);
  const needsPadding = dataToDecode.length % 4;

  if (needsPadding !== 0) {
    const paddingSize = 4 - needsPadding;
    dataToDecode += "=".repeat(paddingSize);
  }

  return JSON.parse(Buffer.from(dataToDecode, "base64").toString("binary"));
}
