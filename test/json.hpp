// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// json.hpp — reading the corpus, and only that.
//
// Two corpora are read from C++ and they do not share a shape: this repo's
// vectors/ is an array of flat rows, luxfi/conformance's is nested. One reader
// answers both, because two readers would be two opinions about what the bytes
// say.
//
// Numbers are kept as their literal text. A uint64 near MaxUint64 does not
// survive a round trip through a double, and both corpora carry stake floors
// that sit there deliberately.
//
// Not a general JSON library: it reads, it never writes, and every malformed
// input throws rather than being skipped past. A harness that quietly accepts a
// corpus it could not parse has checked nothing.

#pragma once

#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace json {

class Value {
public:
    enum class Kind { Null, Bool, Number, String, Array, Object };

    [[nodiscard]] Kind kind() const noexcept { return kind_; }
    [[nodiscard]] bool is_object() const noexcept { return kind_ == Kind::Object; }
    [[nodiscard]] bool is_array() const noexcept { return kind_ == Kind::Array; }

    // The literal text of a scalar: the string's contents, or the number and
    // boolean exactly as written.
    [[nodiscard]] const std::string& text() const {
        if (kind_ == Kind::Array || kind_ == Kind::Object) throw std::runtime_error("not a scalar");
        return text_;
    }

    [[nodiscard]] std::uint64_t u64() const { return std::stoull(text()); }
    [[nodiscard]] bool boolean() const { return text() == "true"; }

    // Array elements, or an object's values in the order the file lists them.
    [[nodiscard]] const std::vector<Value>& items() const noexcept { return items_; }
    [[nodiscard]] std::size_t size() const noexcept { return items_.size(); }

    [[nodiscard]] bool has(std::string_view key) const noexcept { return find(key) != nullptr; }

    // A field named but absent is a corpus that does not carry what a check
    // needs, which is a failure of the corpus and not something to default.
    [[nodiscard]] const Value& at(std::string_view key) const {
        if (const Value* v = find(key)) return *v;
        throw std::runtime_error("corpus object has no field " + std::string(key));
    }

    [[nodiscard]] const Value& operator[](std::size_t i) const {
        if (i >= items_.size()) throw std::runtime_error("corpus index out of range");
        return items_[i];
    }

    // The keys of an object, in file order.
    [[nodiscard]] const std::vector<std::string>& keys() const noexcept { return keys_; }

private:
    friend class Parser;

    [[nodiscard]] const Value* find(std::string_view key) const noexcept {
        for (std::size_t i = 0; i < keys_.size(); ++i)
            if (keys_[i] == key) return &items_[i];
        return nullptr;
    }

    Kind kind_ = Kind::Null;
    std::string text_;
    std::vector<std::string> keys_;  // Object only, parallel to items_
    std::vector<Value> items_;
};

class Parser {
public:
    explicit Parser(std::string_view s) : s_(s) {}

    Value parse() {
        Value v = value();
        skip();
        if (i_ != s_.size()) fail("trailing bytes after the top-level value");
        return v;
    }

private:
    std::string_view s_;
    std::size_t i_ = 0;

    [[noreturn]] void fail(const std::string& why) const {
        throw std::runtime_error("corpus at byte " + std::to_string(i_) + ": " + why);
    }

    void skip() noexcept {
        while (i_ < s_.size() && (s_[i_] == ' ' || s_[i_] == '\t' || s_[i_] == '\n' || s_[i_] == '\r'))
            ++i_;
    }
    char peek() {
        skip();
        if (i_ >= s_.size()) fail("unexpected end");
        return s_[i_];
    }
    char get() {
        const char c = peek();
        ++i_;
        return c;
    }
    void expect(char c) {
        if (get() != c) fail(std::string("expected '") + c + "'");
    }

    static void utf8(std::string& out, std::uint32_t cp) {
        if (cp < 0x80) {
            out.push_back(static_cast<char>(cp));
        } else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    }

    std::string string() {
        expect('"');
        std::string out;
        for (;;) {
            if (i_ >= s_.size()) fail("unterminated string");
            const char c = s_[i_++];
            if (c == '"') return out;
            if (c != '\\') {
                out.push_back(c);
                continue;
            }
            if (i_ >= s_.size()) fail("escape at end of input");
            switch (const char e = s_[i_++]) {
                case '"': case '\\': case '/': out.push_back(e); break;
                case 'b': out.push_back('\b'); break;
                case 'f': out.push_back('\f'); break;
                case 'n': out.push_back('\n'); break;
                case 'r': out.push_back('\r'); break;
                case 't': out.push_back('\t'); break;
                case 'u': {
                    if (i_ + 4 > s_.size()) fail("truncated \\u escape");
                    std::uint32_t cp = 0;
                    for (int k = 0; k < 4; ++k) {
                        const char h = s_[i_++];
                        const int d = (h >= '0' && h <= '9')   ? h - '0'
                                      : (h >= 'a' && h <= 'f') ? h - 'a' + 10
                                      : (h >= 'A' && h <= 'F') ? h - 'A' + 10
                                                               : -1;
                        if (d < 0) fail("bad hex in \\u escape");
                        cp = cp * 16 + static_cast<std::uint32_t>(d);
                    }
                    // Go's encoder escapes only <, > and & plus control
                    // characters, all of which are in the basic plane. A
                    // surrogate half would mean a corpus this reader would
                    // silently mangle, so it says so instead.
                    if (cp >= 0xD800 && cp <= 0xDFFF) fail("surrogate pair in corpus string");
                    utf8(out, cp);
                    break;
                }
                default: fail("unknown escape");
            }
        }
    }

    Value scalar() {
        const std::size_t start = i_;
        while (i_ < s_.size() && s_[i_] != ',' && s_[i_] != '}' && s_[i_] != ']' && s_[i_] != ' ' &&
               s_[i_] != '\t' && s_[i_] != '\n' && s_[i_] != '\r')
            ++i_;
        if (i_ == start) fail("empty scalar");
        Value v;
        v.text_ = std::string(s_.substr(start, i_ - start));
        v.kind_ = (v.text_ == "true" || v.text_ == "false") ? Value::Kind::Bool
                  : (v.text_ == "null")                     ? Value::Kind::Null
                                                            : Value::Kind::Number;
        return v;
    }

    Value value() {
        switch (peek()) {
            case '{': return object();
            case '[': return array();
            case '"': {
                Value v;
                v.kind_ = Value::Kind::String;
                v.text_ = string();
                return v;
            }
            default: return scalar();
        }
    }

    Value array() {
        Value v;
        v.kind_ = Value::Kind::Array;
        expect('[');
        if (peek() == ']') {
            ++i_;
            return v;
        }
        for (;;) {
            v.items_.push_back(value());
            const char c = get();
            if (c == ']') return v;
            if (c != ',') fail("expected ',' or ']'");
        }
    }

    Value object() {
        Value v;
        v.kind_ = Value::Kind::Object;
        expect('{');
        if (peek() == '}') {
            ++i_;
            return v;
        }
        for (;;) {
            if (peek() != '"') fail("object keys are strings");
            v.keys_.push_back(string());
            expect(':');
            v.items_.push_back(value());
            const char c = get();
            if (c == '}') return v;
            if (c != ',') fail("expected ',' or '}'");
        }
    }
};

[[nodiscard]] inline Value parse(std::string_view s) { return Parser(s).parse(); }

}  // namespace json
