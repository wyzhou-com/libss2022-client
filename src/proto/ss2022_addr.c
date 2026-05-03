#include "ss2022_internal.h"

int ss2022_addr_encoded_len(const ss2022_addr *addr, size_t *out_len) {
    if (addr == NULL || out_len == NULL) {
        return SS2022_ERR_INVALID_ARG;
    }

    if (addr->type == SS2022_ADDR_IPV4) {
        *out_len = 1u + 4u + 2u;
        return SS2022_OK;
    }
    if (addr->type == SS2022_ADDR_IPV6) {
        *out_len = 1u + 16u + 2u;
        return SS2022_OK;
    }
    if (addr->type == SS2022_ADDR_DOMAIN) {
        if (addr->u.domain.len == 0u) {
            return SS2022_ERR_BAD_ADDR;
        }
        *out_len = 1u + 1u + (size_t)addr->u.domain.len + 2u;
        return SS2022_OK;
    }
    return SS2022_ERR_BAD_ADDR;
}

int ss2022_addr_encode(const ss2022_addr *addr, uint8_t *out,
                       size_t out_cap, size_t *out_len) {
    if (addr == NULL || out == NULL || out_len == NULL) {
        return SS2022_ERR_INVALID_ARG;
    }

    size_t need = 0u;
    int ret = ss2022_addr_encoded_len(addr, &need);
    if (ret != SS2022_OK) {
        return ret;
    }

    if (out_cap < need) {
        return SS2022_ERR_BUFFER_TOO_SMALL;
    }

    size_t pos = 0u;
    out[pos++] = (uint8_t)addr->type;
    if (addr->type == SS2022_ADDR_IPV4) {
        memcpy(out + pos, addr->u.ipv4, 4u);
        pos += 4u;
    } else if (addr->type == SS2022_ADDR_IPV6) {
        memcpy(out + pos, addr->u.ipv6, 16u);
        pos += 16u;
    } else {
        out[pos++] = addr->u.domain.len;
        memcpy(out + pos, addr->u.domain.name, addr->u.domain.len);
        pos += addr->u.domain.len;
    }
    ss2022_write_u16be(out + pos, addr->port);
    pos += 2u;
    *out_len = pos;
    return SS2022_OK;
}

int ss2022_addr_decode(const uint8_t *in, size_t in_len,
                       ss2022_addr *addr, size_t *consumed) {
    if (in == NULL || addr == NULL || consumed == NULL) {
        return SS2022_ERR_INVALID_ARG;
    }
    if (in_len < 1u) {
        return SS2022_ERR_MALFORMED;
    }

    size_t pos = 1u;
    uint8_t atyp = in[0];
    memset(addr, 0, sizeof(*addr));
    addr->type = (ss2022_addr_type_t)atyp;

    if (atyp == (uint8_t)SS2022_ADDR_IPV4) {
        if (in_len < pos + 4u + 2u) {
            return SS2022_ERR_MALFORMED;
        }
        memcpy(addr->u.ipv4, in + pos, 4u);
        pos += 4u;
    } else if (atyp == (uint8_t)SS2022_ADDR_IPV6) {
        if (in_len < pos + 16u + 2u) {
            return SS2022_ERR_MALFORMED;
        }
        memcpy(addr->u.ipv6, in + pos, 16u);
        pos += 16u;
    } else if (atyp == (uint8_t)SS2022_ADDR_DOMAIN) {
        if (in_len < pos + 1u) {
            return SS2022_ERR_MALFORMED;
        }
        uint8_t len = in[pos++];
        if (len == 0u || in_len < pos + (size_t)len + 2u) {
            return SS2022_ERR_BAD_ADDR;
        }
        addr->u.domain.len = len;
        memcpy(addr->u.domain.name, in + pos, len);
        pos += len;
    } else {
        return SS2022_ERR_BAD_ADDR;
    }

    addr->port = ss2022_read_u16be(in + pos);
    pos += 2u;
    *consumed = pos;
    return SS2022_OK;
}
