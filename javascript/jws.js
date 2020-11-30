class VerificationError extends Error {
    constructor(message) {
        super(message);
        this.name = "VerificationError";
    }
}

class NbfError extends Error {
    constructor(message) {
        super(message);
        this.name = "NbfError";
    }
}

class ExpError extends Error {
    constructor(message) {
        super(message);
        this.name = "ExpError";
    }
}

const JWS = (() => {
    const Ob = function () {
        this.supported_algorithms = {
            "HS256": "SHA-256",
            "HS384": "SHA-384",
            "HS512": "SHA-512"
        };
        /**
         *
         * @param data_map map of claims, as an associative array
         * @param key secret key
         * @param nbf not before, given as a Unix timestamp
         * @param exp_after expire after how many milliseconds since time of issue
         * @param algorithm algorithm to use in signature generation
         * @returns {Promise<string>} jwt string on successful promise resolve
         */
        this.encode = async (data_map, key, nbf, exp_after, algorithm = "HS256") => {
            check_algorithm_support(algorithm);
            if (Array.isArray(data_map) || Object.keys(data_map).filter(item => typeof(item) == "string").length === 0) {
                throw TypeError("Data map needs to be an associative array");
            }

            let header = encode_header(algorithm);
            let payload = encode_payload(data_map, nbf, exp_after);
            let signature = await encode_signature(header, payload, algorithm, key);

            return `${header}.${payload}.${signature}`;
        };
        /**
         * w
         * @param token jwt string
         * @param key secret key
         * @returns {Promise<*>} map of claims on successful promise resolve
         * @throws ExpException jwt is expired
         * @throws NbfException jwt not yet active
         * @throws VerificationException jwt signature verification failed
         */
        this.decode = async (token, key) => {
            let token_segments = token.split(".");
            let encoded_header = token_segments[0];
            let encoded_payload = token_segments[1];
            let encoded_signature = token_segments[2];

            let header = decode_header(encoded_header);
            check_algorithm_support(header["alg"]);

            if (!await verify_signature(encoded_header, encoded_payload, encoded_signature, header["alg"], key)) {
                throw new VerificationError("Signature verification failed");
            } else {
                let current_timestamp = Date.now();
                let payload = decode_payload(encoded_payload);

                if (current_timestamp < payload["nbf"]) {
                    throw new NbfError(`Not yet active. Becomes active at ${payload["nbf"]}`);
                } else if (current_timestamp > payload["exp"]) {
                    throw new ExpError(`Expired at ${payload["exp"]}`);
                } else {
                    return payload["payload"];
                }
            }
        };
    };

    function check_algorithm_support(algorithm) {
        if (!Object.keys(ob_object.supported_algorithms).includes(algorithm)) {
            throw(`${algorithm} not supported. Accepts: ${Object.keys(ob_object.supported_algorithms)}`);
        }
    }

    function encode_header(algorithm) {
        let ob = {"typ": "JWT", "alg": algorithm};
        return url_safe_encode(ob);
    }

    function decode_header(encoded_header) {
        return url_safe_decode(encoded_header);
    }

    function encode_payload(data_map, nbf, exp_after) {
        let current_time = Date.now();

        let ob = {
            "iat": current_time,  // Issued at time
            "nbf": nbf,  // Not before
            "exp": current_time + exp_after,  // Expiration
            "payload": data_map
        };

        return url_safe_encode(ob);
    }

    function decode_payload(encoded_payload) {
        return url_safe_decode(encoded_payload);
    }

    async function encode_signature(encoded_header, encoded_payload, algorithm, key) {
        const encoder = new TextEncoder();

        let crypto_key = await crypto.subtle.importKey(
            "raw", encoder.encode(key),
            {name: "HMAC", hash: {name: ob_object.supported_algorithms[algorithm]}}, false,
            ["sign"]
        );
        let signature = await crypto.subtle.sign(
            "HMAC", crypto_key, encoder.encode(`${encoded_header}.${encoded_payload}`)
        );
        let hex = Array.prototype.map.call(new Uint8Array(signature), x => ("00" + x.toString(16)).slice(-2)).join("");

        return url_safe_encode(hex, false);
    }

    async function verify_signature(encoded_header, encoded_payload, encoded_signature, algorithm, key) {
        const encoder = new TextEncoder();
        let hex = url_safe_decode(encoded_signature, false);
        let uint8 = new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

        let crypto_key = await crypto.subtle.importKey(
            "raw", encoder.encode(key),
            {name: "HMAC", hash: {name: ob_object.supported_algorithms[algorithm]}}, false,
            ["verify"]
        );
        return await crypto.subtle.verify(
            "HMAC", crypto_key,
            uint8,
            encoder.encode(`${encoded_header}.${encoded_payload}`)
        );
    }

    function url_safe_encode(data, encode_as_json = true) {
        const r_strip = (s, x) => {
            while (s.endsWith(x)) {
                s = s.slice(0, -1);
            }
            return s;
        };

        if (encode_as_json) {
            return r_strip(btoa(JSON.stringify(data)), "=");
        } else {
            return r_strip(btoa(data), "=");
        }
    }

    function url_safe_decode(data, decode_as_json = true) {
        if (decode_as_json) {
            return JSON.parse(atob(data));
        } else {
            return atob(data);
        }
    }

    const ob_object = new Ob();
    return ob_object;
})();
