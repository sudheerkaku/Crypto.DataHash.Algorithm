# Crypto.DataHash.Algorithm.js

[![Packagist](https://img.shields.io/packagist/l/doctrine/orm.svg?maxAge=2592000)]()
[![PyPI](https://img.shields.io/pypi/status/Django.svg?maxAge=2592000)]()

> Cryptography/Data/Hash Algorithms (MD5, SHA1, SHA256, SHA512) with HMAC.

## Why

'Crypto.DataHash.Algorithm.js' allows web sites to perform simple cryptography on clients, enabling some useful applications:
**Protecting Passwords, Generating Passwords, Self-Decrypting Pages etc.,**

## Setup or Usage

First, either include the script located on the `dist` folder or load it from [a third-party CDN provider](//cdn.jsdelivr.net/Crypto.DataHash.Algorithm/1.0/Crypto.DataHash.Algorithm.min.js).

```html
<script src="dist/Crypto.DataHash.Algorithm.min.js"></script>
or
<script src="//cdn.jsdelivr.net/Crypto.DataHash.Algorithm/1.0/Crypto.DataHash.Algorithm.min.js"></script>
```

Crypto.DataHash.Algorithm.js works using javascript
```html
<div>
    <h3>HEX</h3>
    <div><span>INPUT </span><input id="HEXMD5" style="height:25px;" type="text" size="25"></div>
    <div><span>Output Uppercase </span><input id="HEXMD5CASE" type="checkbox"></div>
    <div><span>RESULT </span><input id="HEXMD5Value" style="height:25px;" type="text" size="25"></div>
    <input class="pricing__action" onclick="document.getElementById('HEXMD5Value').value = Crypto & Crypto.Algorithm & Crypto.Algorithm.HEX_MD5(document.getElementById('HEXMD5').value, document.getElementById('HEXMD5CASE').checked)" type="button" value="HEX MD5">
</div>
```

the above example is for MD5, each Hash Algorithm inputs and functions are different

```js
<!-- HEX -->
Crypto.Algorithm.HEX_MD5(input, hexCase);
Crypto.Algorithm.HEX_SHA1(input, hexCase);
Crypto.Algorithm.HEX_SHA256(input, hexCase);
Crypto.Algorithm.HEX_SHA512(input, hexCase);
Crypto.Algorithm.HEX_HMAC_MD5(key, data, hexCase);
Crypto.Algorithm.HEX_HMAC_SHA1(key, data, hexCase);
Crypto.Algorithm.HEX_HMAC_SHA256(key, data, hexCase);
Crypto.Algorithm.HEX_HMAC_SHA512(key, data, hexCase);
<!-- BASE64 -->
Crypto.Algorithm.B64_MD5(input, b64Padding);
Crypto.Algorithm.B64_SHA1(input, b64Padding);
Crypto.Algorithm.B64_SHA256(input, b64Padding);
Crypto.Algorithm.B64_SHA512(input, b64Padding);
Crypto.Algorithm.B64_HMAC_MD5(key, data, b64Padding);
Crypto.Algorithm.B64_HMAC_SHA1(key, data, b64Padding);
Crypto.Algorithm.B64_HMAC_SHA256(key, data, b64Padding);
Crypto.Algorithm.B64_HMAC_SHA512(key, data, b64Padding);
<!-- ANY -->
Crypto.Algorithm.ANY_MD5(input, encoding);
Crypto.Algorithm.ANY_SHA1(input, encoding);
Crypto.Algorithm.ANY_SHA256(input, encoding);
Crypto.Algorithm.ANY_SHA512(input, encoding);
Crypto.Algorithm.ANY_HMAC_MD5(key, data, encoding);
Crypto.Algorithm.ANY_HMAC_SHA1(key, data, encoding);
Crypto.Algorithm.ANY_HMAC_SHA256(key, data, encoding);
Crypto.Algorithm.ANY_HMAC_SHA512(key, data, encoding);
```

## Browser Support

<img src="https://raw.githubusercontent.com/alrra/browser-logos/master/chrome/chrome_48x48.png" width="48px" height="48px" alt="Chrome logo"> | <img src="https://raw.githubusercontent.com/alrra/browser-logos/master/firefox/firefox_48x48.png" width="48px" height="48px" alt="Firefox logo"> | <img src="https://raw.githubusercontent.com/alrra/browser-logos/master/edge/edge_48x48.png" width="48px" height="48px" alt="Edge"> | <img src="https://raw.githubusercontent.com/alrra/browser-logos/master/internet-explorer/internet-explorer_48x48.png" width="48px" height="48px" alt="Internet Explorer logo"> | <img src="https://raw.githubusercontent.com/alrra/browser-logos/master/opera/opera_48x48.png" width="48px" height="48px" alt="Opera logo"> | <img src="http://clipboardjs.com/assets/images/safari.png" width="48px" height="48px" alt="Safari logo"> |
|:---:|:---:|:---:|:---:|:---:|:---:|
| ✔ | ✔ | ✔ | ✔ | ✔ | ✔ |