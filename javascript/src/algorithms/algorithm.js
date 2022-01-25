export const Algorithm = function (supportedAlgorithms, constructor = null) {
  this.constructor = constructor === null ? this.constructor : constructor;
  if (this.constructor === Algorithm) {
    throw new Error("Abstract function");
  }

  this.supportedAlgorithms = supportedAlgorithms;

  this.generateSignature = (
    encodedHeader,
    encodedPayload,
    algorithm,
    secretKey
  ) => {
    throw new Error("Abstract property");
  };

  this.verifySignature = (
    encodedHeader,
    encodedPayload,
    algorithm,
    signature,
    secretKey
  ) => {
    throw new Error("Abstract property");
  };

  this.isAlgorithmSupported = (algorithm) => {
    for (const i of Object.keys(this.supportedAlgorithms)) {
      if (algorithm === i) {
        return true;
      }
    }
    return false;
  };
};
