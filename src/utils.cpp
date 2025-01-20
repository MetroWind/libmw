#include <algorithm>
#include <array>
#include <expected>
#include <span>
#include <stddef.h>
#include <string>
#include <string_view>
#include <vector>

#include "utils.hpp"
#include "error.hpp"

namespace
{

constexpr unsigned char BASE64_TABLE[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

} // namespace

namespace mw
{

// Shamelessly copied and modifed from
// http://web.mit.edu/freebsd/head/contrib/wpa/src/utils/base64.c.
std::string base64Encode(std::span<unsigned char> data, bool newline, bool pad)
{
    size_t olen = data.size() * 4 / 3 + 4;
    olen += olen / 72;

    std::string result;
    result.reserve(olen);

    auto end = data.end();
    auto in = data.begin();
    // pos = out;
    int line_len = 0;
    while(end - in >= 3)
    {
        result.push_back(BASE64_TABLE[in[0] >> 2]);
        result.push_back(BASE64_TABLE[((in[0] & 0x03) << 4) | (in[1] >> 4)]);
        result.push_back(BASE64_TABLE[((in[1] & 0x0f) << 2) | (in[2] >> 6)]);
        result.push_back(BASE64_TABLE[in[2] & 0x3f]);
        in += 3;
        if(newline)
        {
            line_len += 4;
            if (line_len >= 72)
            {
                result.push_back('\n');
                line_len = 0;
            }
        }
    }

    if(end - in)
    {
        result.push_back(BASE64_TABLE[in[0] >> 2]);
        if(end - in == 1)
        {
            result.push_back(BASE64_TABLE[(in[0] & 0x03) << 4]);
            if(pad)
            {
                result.push_back('=');
            }
        }
        else
        {
            result.push_back(
                BASE64_TABLE[((in[0] & 0x03) << 4) | (in[1] >> 4)]);
            result.push_back(BASE64_TABLE[(in[1] & 0x0f) << 2]);
        }
        if(pad)
        {
            result.push_back('=');
        }
        line_len += 4;
    }

    if(line_len && newline) result.push_back('\n');
    return result;
}

// Shamelessly copied and modifed from
// http://web.mit.edu/freebsd/head/contrib/wpa/src/utils/base64.c.
E<std::vector<unsigned char>> base64Decode(std::string_view data)
{
    std::array<unsigned char, 256> dtable;
    std::fill(dtable.begin(), dtable.end(), 0x80);
    std::array<unsigned char, 4> block;
    unsigned char tmp;

    for (size_t i = 0; i < sizeof(BASE64_TABLE) - 1; i++)
    {
        dtable[BASE64_TABLE[i]] = static_cast<unsigned char>(i);
    }
    dtable['='] = 0;

    // Count the number of valid base64 chars.
    size_t count = 0;
    for(char c: data)
    {
        if(dtable[c] != 0x80) count++;
    }
    if(count == 0)
    {
        return std::unexpected(runtimeError("Invalid base64 string"));
    }

    std::vector<unsigned char> result;
    // Usually with padding, count % 4 is always 0. The required
    // output length is count / 4 * 3. However we don’t require
    // padding. So we reserve some extra bytes to account for that.
    result.reserve(((count / 4) + 1) * 3);

    count = 0;
    for(char c: data)
    {
        tmp = dtable[c];
        if (tmp == 0x80) continue;
        if (c == '=') break;
        block[count] = tmp;
        count++;
        if(count == 4)
        {
            result.push_back((block[0] << 2) | (block[1] >> 4));
            result.push_back((block[1] << 4) | (block[2] >> 2));
            result.push_back((block[2] << 6) | block[3]);
            count = 0;
        }
    }

    // Now we have exhausted the part before the padding. “Count” is
    // the number of chars before the padding. Since we always push 3
    // bytes each time (for 4 base64 chars), depending on how many
    // paddings that are supposed to be there, we might have pushed
    // too many chars.
    if(count % 4 == 2)
    {
        result.push_back((block[0] << 2) | (block[1] >> 4));
    }
    else if(count % 4 == 1)
    {
        result.push_back((block[1] << 4) | (block[2] >> 2));
        result.push_back((block[2] << 6) | block[3]);
    }

    return result;
}

} // namespace mw
