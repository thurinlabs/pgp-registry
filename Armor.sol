// SPDX-License-Identifier: MIT
pragma solidity 0.8.37;

/**
 * @title Armor
 * @notice OpenPGP ASCII armor (base64 in 64-character lines, a CRC-24 checksum line) and back. Only
 *         the views use it, so keys and statements paste straight into gpg; writes never depend on it.
 *         The loops are assembly so a 16 KB key stays well inside a node's gas limit for one call.
 */
library Armor {
    bytes internal constant ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    /// CRC-24 of every byte value (256 entries of 3 bytes), for the table-driven checksum.
    bytes internal constant CRC_TABLE = hex"000000864cfb8ad50d0c99f693e6e115aa1a1933ec9f7f17a1813927cdc22b5434ad18cf3267d8b42b23b8b2d53efe2ec54e894302724f9b84c9d77f56a868d0e493dc7d655a319e64cfb0e2834bee1abd685646f729517165aa7dfc5cfbb0a70cd1e98a9d128604e400481f9f3708197bf315e20593aefead50d02b1c2b2785dda1c9263eb631b8facab4633c322fc7c99f604fd39b434a6dc506965a7981dc357ad0ac8c56e077681e59ee52a2e2cb546487affbf8b87db443712db5f7614e19a3d29fef299376df153a248a45330c09c800903e86dcc5b822eb3e6e1032f7e6b4bb1d2bc40aad88f1a11107275dfcdced5b5aa1a0563856d074ad4f0bbac94741c5deb743924c7d6c62fb2099f7b96f71f594ee8a8368c678645f8ee2137515723b933ec09fa73619ebcd8694da00d8210c41d78a0d2cb4f30232bff93e260fb86af42715e3a15918adc0ee2b8c15d03cb25670495ae9bfdca54443da53c596a8c90f5e4f43a571bd8bf7f170fb68867d247de25b6a641791688e67eec29c3347a4b50b5fb992a93fde52a0a14526edbe2a7448ac38b392c69d148a661813909e5f6b01207c876c878bf5710db98af6092d7045d67cdc20fa90db65efcce3a337ef3ac169763a578814d1c4efdd5d195b11e2c46ef542220e4ebbf8c8f7033f964db9dab6b54340330fbbac70ac2a3c5726a5a1a0e95a9e1774185b8f14c279928e820df1958bbd6e872498016863fad8c47c943f700dc9f64132693e25ef72dee3eb2865a7d35b59fddd1506d18cf057c00bc8bf1c4ef3e7426a11c426ea2ae476aca88da0317b267d80b902973f4e6c33d79ab59b618b654f0d29b401b04287fcb91883ae9ecf559256a3141a58efaaff69e604657ff2e333097c4c1efa00e5f6991370d5e84e2bc6c8673dc4fecb42b230ddcd275b81dc57182ad154d126359fa07964ace0922aac69b5d37e339f853f0673b94a8887b4a601f85d0d61ab8b2d50145247921ebc9e874a18cbb1e37b166537ed69ae1befe2e0709df7f6d10cfa48fa7c040142fa2fc4b6d4c82f224e63d9d11cce5750355bc9c3dd8538";
    /// ASCII → base64 value; 0xFF for characters that aren't base64.
    bytes internal constant DECODE_TABLE = hex"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3effffff3f3435363738393a3b3c3dffffffffffffff000102030405060708090a0b0c0d0e0f10111213141516171819ffffffffffff1a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233ffffffffff";

    error NotArmored();
    error BadBase64();
    error BadArmorChecksum();
    error UnsupportedHeader();

    // ─── Building armor ──────────────────────────────────────────────────────

    /// @notice `-----BEGIN PGP <label>-----`, a blank line, base64 lines, `=` + checksum, END line.
    function armor(string memory label, bytes memory data) internal pure returns (string memory) {
        return string.concat(
            "-----BEGIN PGP ", label, "-----\n\n",
            string(_encode(data, true)), "\n",
            "=", string(_encode(_crcBytes(crc24(data)), false)), "\n",
            "-----END PGP ", label, "-----\n"
        );
    }

    /// @notice A clearsigned message: the header, the signed text, then the armored signature.
    ///         `Hash:` is required by gpg (except for version 6 signatures) and is read from the signature.
    function clearsign(string memory text, bytes memory signature) internal pure returns (string memory) {
        (uint8 version, string memory hash) = signatureHash(signature);
        string memory header = version != 6 && bytes(hash).length > 0
            ? string.concat("-----BEGIN PGP SIGNED MESSAGE-----\nHash: ", hash, "\n\n")
            : "-----BEGIN PGP SIGNED MESSAGE-----\n\n";
        return string.concat(header, text, "\n", armor("SIGNATURE", signature));
    }

    /// @notice Standard base64 with padding, on one line.
    function base64(bytes memory data) internal pure returns (bytes memory) {
        return _encode(data, false);
    }

    /// @notice CRC-24 as OpenPGP defines it (initial value 0xB704CE, polynomial 0x1864CFB).
    function crc24(bytes memory data) internal pure returns (uint256 crc) {
        bytes memory table = CRC_TABLE;
        assembly ("memory-safe") {
            crc := 0xB704CE
            let tp := add(table, 0x20)
            let p := add(data, 0x20)
            let e := add(p, mload(data))
            for {} lt(p, e) { p := add(p, 1) } {
                let idx := and(xor(shr(16, crc), byte(0, mload(p))), 0xff)
                crc := and(xor(shl(8, crc), shr(232, mload(add(tp, mul(idx, 3))))), 0xffffff)
            }
        }
    }

    /// @notice The signature packet's version and its hash algorithm's armor name. Reads the packet
    ///         header and one body byte; nothing else. (0, "") if it isn't a readable signature packet.
    function signatureHash(bytes memory sig) internal pure returns (uint8 version, string memory name) {
        uint256 off = _bodyOffset(sig);
        if (off == type(uint256).max || sig.length < off + 4) return (0, "");
        version = uint8(sig[off]);
        uint8 h = uint8(sig[off + 3]);
        if (h == 8) name = "SHA256";
        else if (h == 10) name = "SHA512";
        else if (h == 9) name = "SHA384";
        else if (h == 11) name = "SHA224";
        else if (h == 12) name = "SHA3-256";
        else if (h == 14) name = "SHA3-512";
        else if (h == 2) name = "SHA1";
        else if (h == 3) name = "RIPEMD160";
    }

    // ─── Reading armor ───────────────────────────────────────────────────────

    /**
     * @notice The bytes inside an armored block. Whitespace anywhere is ignored (contract tools may
     *         flatten line breaks when you paste), armor header lines are skipped, and the checksum
     *         is checked when present. For a clearsigned message, the signature block is used.
     */
    function decode(string memory armored) internal pure returns (bytes memory data) {
        bytes memory t = bytes(armored);
        (uint256 start, uint256 end) = _body(t);
        start = _skipHeaders(t, start, end);

        // Checksum: the last whitespace-separated token that starts with '=' and has 5 characters, or,
        // when a single-line form field dropped the line breaks, '=' + 4 characters fused onto the end
        // of the data (base64 comes in fours, so exactly one extra character gives it away).
        uint256 limit = end;
        uint256 csStart = type(uint256).max;
        {
            uint256 i = end;
            while (i > start && _isSpace(t[i - 1])) i--;
            uint256 tokEnd = i;
            while (i > start && !_isSpace(t[i - 1])) i--;
            if (tokEnd - i == 5 && t[i] == "=") {
                csStart = i;
                limit = i;
            } else if (tokEnd - start >= 5 && t[tokEnd - 5] == "=" && t[tokEnd - 4] != "=") {
                uint256 n;
                for (uint256 k = start; k < tokEnd; ++k) if (!_isSpace(t[k])) n++;
                if (n % 4 == 1) { csStart = tokEnd - 5; limit = csStart; }
            }
        }

        data = _decodeTokens(t, start, limit);
        if (csStart != type(uint256).max) {
            bytes memory cs = new bytes(4);
            for (uint256 k; k < 4; ++k) cs[k] = t[csStart + 1 + k];
            bytes memory want = _decodeTokens(cs, 0, 4);
            if (want.length != 3) revert BadArmorChecksum();
            uint256 given = (uint256(uint8(want[0])) << 16) | (uint256(uint8(want[1])) << 8) | uint256(uint8(want[2]));
            if (given != crc24(data)) revert BadArmorChecksum();
        }
    }

    // ─── Internals ───────────────────────────────────────────────────────────

    /// Base64 with padding; with `wrap`, a line break after every 64 characters.
    function _encode(bytes memory data, bool wrap) private pure returns (bytes memory out) {
        uint256 len = data.length;
        if (len == 0) return out;
        uint256 encLen = 4 * ((len + 2) / 3);
        out = new bytes(wrap ? encLen + (encLen - 1) / 64 : encLen);
        bytes memory table = ALPHABET;
        assembly ("memory-safe") {
            let tbl := add(table, 1) // low byte of mload(tbl + i) is ALPHABET[i]
            let src := add(data, 0x20)
            let end := add(src, len)
            let dst := add(out, 0x20)
            let col := 0
            for {} lt(src, end) { src := add(src, 3) } {
                let n := shr(232, mload(src))
                let left := sub(end, src)
                if lt(left, 3) { n := and(n, xor(0xffffff, shr(mul(left, 8), 0xffffff))) } // drop bytes past the end
                mstore8(dst, mload(add(tbl, and(shr(18, n), 63))))
                mstore8(add(dst, 1), mload(add(tbl, and(shr(12, n), 63))))
                mstore8(add(dst, 2), mload(add(tbl, and(shr(6, n), 63))))
                mstore8(add(dst, 3), mload(add(tbl, and(n, 63))))
                dst := add(dst, 4)
                col := add(col, 4)
                if and(wrap, and(eq(col, 64), gt(sub(end, src), 3))) {
                    mstore8(dst, 10)
                    dst := add(dst, 1)
                    col := 0
                }
            }
            switch mod(len, 3)
            case 1 { mstore8(sub(dst, 1), 61) mstore8(sub(dst, 2), 61) }
            case 2 { mstore8(sub(dst, 1), 61) }
        }
    }

    /// Decode the base64 in t[start, limit), skipping whitespace. In a flattened paste a header can't be
    /// told from data, so a ':' there is refused. Four characters at a time when all four are base64.
    function _decodeTokens(bytes memory t, uint256 start, uint256 limit) private pure returns (bytes memory out) {
        out = new bytes(((limit - start) * 3) / 4 + 3);
        bytes memory table = DECODE_TABLE;
        bool flat = _find(t, "\n", start) >= limit; // no line break in the region
        bool bad;
        bool header;
        assembly ("memory-safe") {
            function isSpace(c) -> r { r := or(or(eq(c, 32), eq(c, 9)), or(eq(c, 10), eq(c, 13))) }
            function lookup(c, dt) -> v {
                v := 0xff
                if lt(c, 128) { v := byte(0, mload(add(dt, c))) }
            }
            // Decode t[from, to) into dst, skipping whitespace. State: bit accumulator, pending bits,
            // characters seen, '=' seen, and a bad flag.
            function run(tp, dt, from, to, acc0, bits0, chars0, pads0, dst0) -> acc, bits, chars, pads, dst, badc {
                acc := acc0
                bits := bits0
                chars := chars0
                pads := pads0
                dst := dst0
                for { let i := from } lt(i, to) {} {
                    let w := mload(add(tp, i))
                    let c := byte(0, w)
                    if isSpace(c) { i := add(i, 1) continue }
                    if and(iszero(bits), iszero(gt(add(i, 4), to))) {
                        let v0 := lookup(c, dt)
                        let v1 := lookup(byte(1, w), dt)
                        let v2 := lookup(byte(2, w), dt)
                        let v3 := lookup(byte(3, w), dt)
                        if iszero(or(or(eq(v0, 0xff), eq(v1, 0xff)), or(eq(v2, 0xff), eq(v3, 0xff)))) {
                            if pads { badc := 1 }
                            let n := or(or(shl(18, v0), shl(12, v1)), or(shl(6, v2), v3))
                            mstore8(dst, shr(16, n))
                            mstore8(add(dst, 1), shr(8, n))
                            mstore8(add(dst, 2), n)
                            dst := add(dst, 3)
                            chars := add(chars, 4)
                            i := add(i, 4)
                            continue
                        }
                    }
                    chars := add(chars, 1)
                    switch eq(c, 61) // '='
                    case 1 { pads := add(pads, 1) }
                    default {
                        let v := lookup(c, dt)
                        if or(eq(v, 0xff), pads) { badc := 1 }
                        acc := or(shl(6, acc), v)
                        bits := add(bits, 6)
                        if iszero(lt(bits, 8)) {
                            bits := sub(bits, 8)
                            mstore8(dst, shr(bits, acc))
                            dst := add(dst, 1)
                            acc := and(acc, sub(shl(bits, 1), 1))
                        }
                    }
                    i := add(i, 1)
                }
            }

            let tp := add(t, 0x20)
            let dt := add(table, 0x20)
            let dst := add(out, 0x20)
            let acc := 0
            let bits := 0
            let chars := 0
            let pads := 0
            let b := 0

            if flat {
                for { let i := start } lt(i, limit) { i := add(i, 1) } {
                    if eq(byte(0, mload(add(tp, i))), 58) { header := 1 break } // ':'
                }
            }
            if iszero(header) {
                acc, bits, chars, pads, dst, b := run(tp, dt, start, limit, acc, bits, chars, pads, dst)
                if b { bad := 1 }
            }
            if or(mod(chars, 4), gt(pads, 2)) { bad := 1 }
            mstore(out, sub(dst, add(out, 0x20)))
        }
        if (header) revert UnsupportedHeader();
        if (bad) revert BadBase64();
    }

    function _crcBytes(uint256 crc) private pure returns (bytes memory b) {
        b = new bytes(3);
        // forge-lint: disable-next-line(unsafe-typecast) the checksum is 24 bits, taken a byte at a time
        b[0] = bytes1(uint8(crc >> 16));
        // forge-lint: disable-next-line(unsafe-typecast)
        b[1] = bytes1(uint8(crc >> 8));
        // forge-lint: disable-next-line(unsafe-typecast)
        b[2] = bytes1(uint8(crc));
    }

    /// Where a signature packet's body starts, or type(uint256).max if it isn't one.
    function _bodyOffset(bytes memory p) private pure returns (uint256) {
        uint256 none = type(uint256).max;
        if (p.length < 2) return none;
        uint8 b = uint8(p[0]);
        if (b & 0x80 == 0) return none;
        if (b & 0x40 != 0) {
            if (b & 0x3F != 2) return none;
            uint8 l = uint8(p[1]);
            if (l < 192) return 2;
            if (l < 224) return 3;
            if (l == 255) return 6;
            return none; // partial lengths never occur in a signature packet
        }
        if ((b >> 2) & 0x0F != 2) return none;
        uint8 lt = b & 3;
        if (lt == 0) return 2;
        if (lt == 1) return 3;
        if (lt == 2) return 5;
        return none;
    }

    /// Start and end of the base64 region: after `-----BEGIN PGP …-----`, before `-----END PGP`.
    function _body(bytes memory t) private pure returns (uint256 start, uint256 end) {
        // The last signature block: a clearsigned message's real signature always comes last, and
        // signed text may itself contain an undashed "BEGIN PGP SIGNATURE" line.
        uint256 b = type(uint256).max;
        for (uint256 from; ; ) {
            uint256 hit = _find(t, "-----BEGIN PGP SIGNATURE-----", from);
            if (hit == type(uint256).max) break;
            b = hit;
            from = hit + 1;
        }
        if (b == type(uint256).max) b = _find(t, "-----BEGIN PGP ", 0);
        if (b == type(uint256).max) revert NotArmored();
        uint256 close = _find(t, "-----", b + 15);
        if (close == type(uint256).max) revert NotArmored();
        start = close + 5;
        end = _find(t, "-----END PGP ", start);
        if (end == type(uint256).max) revert NotArmored();
    }

    /// Skip `Name: value` header lines up to the blank line that ends them (when line breaks survive).
    function _skipHeaders(bytes memory t, uint256 start, uint256 end) private pure returns (uint256) {
        uint256 i = start;
        while (i < end && (t[i] == "\r" || t[i] == "\n")) {
            if (t[i] == "\n") { unchecked { ++i; } break; }
            unchecked { ++i; }
        }
        uint256 lineStart = i;
        bool sawHeader;
        while (lineStart < end) {
            uint256 lineEnd = _find(t, "\n", lineStart);
            if (lineEnd >= end) break; // no more line breaks: flattened; the token pass handles it
            uint256 contentEnd = lineEnd;
            if (contentEnd > lineStart && t[contentEnd - 1] == "\r") contentEnd--;
            if (contentEnd == lineStart) return sawHeader ? lineEnd + 1 : start; // blank line
            bool colon;
            for (uint256 k = lineStart; k < contentEnd; ++k) {
                if (t[k] == ":") { colon = true; break; }
            }
            if (!colon) { // data began
                if (sawHeader) revert UnsupportedHeader(); // headers must end with a blank line
                return start;
            }
            sawHeader = true;
            lineStart = lineEnd + 1;
        }
        return start;
    }

    function _isSpace(bytes1 c) private pure returns (bool) {
        return c == " " || c == "\n" || c == "\r" || c == "\t";
    }

    /// First index of `needle` (at most 32 bytes) in `t` at or after `from`. Words that cannot hold the
    /// needle's first byte are skipped 32 bytes at a time.
    function _find(bytes memory t, bytes memory needle, uint256 from) private pure returns (uint256 r) {
        assembly ("memory-safe") {
            r := not(0)
            let n := mload(needle)
            let tl := mload(t)
            let tp := add(t, 0x20)
            let mask := not(shr(mul(n, 8), not(0)))
            let nw := and(mload(add(needle, 0x20)), mask)
            let first := byte(0, nw)
            let ones := 0x0101010101010101010101010101010101010101010101010101010101010101
            let highs := 0x8080808080808080808080808080808080808080808080808080808080808080
            let spread := mul(first, ones)
            for { let i := from } iszero(gt(add(i, n), tl)) {} {
                let w := mload(add(tp, i))
                let x := xor(w, spread)
                if iszero(and(and(sub(x, ones), not(x)), highs)) { i := add(i, 32) continue }
                if eq(and(w, mask), nw) { r := i break }
                i := add(i, 1)
            }
        }
    }
}
