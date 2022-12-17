//--------------------------------------------------------------------------
// Copyright (C) 2014-2022 Cisco and/or its affiliates. All rights reserved.
// Copyright (C) 2003-2013 Sourcefire, Inc.
// Copyright (C) 2003 Brian Caswell <bmc@snort.org>
// Copyright (C) 2003 Michael J. Pomraning <mjp@securepipe.com>
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <pcre.h>

#include <cassert>

#include "detection/ips_context.h"
#include "framework/cursor.h"
#include "framework/ips_option.h"
#include "framework/module.h"
#include "framework/parameter.h"
#include "hash/hash_key_operations.h"
#include "helpers/scratch_allocator.h"
#include "log/messages.h"
#include "main/snort_config.h"
#include "managers/ips_manager.h"
#include "managers/module_manager.h"
#include "profiler/profiler.h"
#include "utils/util.h"
#include <Poco/JWT/Token.h>
#include <Poco/JWT/JWTException.h>

using namespace snort;
using namespace Poco::JWT;

#ifndef PCRE_STUDY_JIT_COMPILE
#define PCRE_STUDY_JIT_COMPILE 0
#endif

//#define NO_JIT // uncomment to disable JIT for Xcode

#ifdef NO_JIT
#define PCRE_STUDY_FLAGS 0
#define pcre_release(x) pcre_free(x)
#else
#define PCRE_STUDY_FLAGS PCRE_STUDY_JIT_COMPILE
#define pcre_release(x) pcre_free_study(x)
#endif

#define SNORT_PCRE_RELATIVE         0x00010 // relative to the end of the last match
#define SNORT_PCRE_INVERT           0x00020 // invert detect
#define SNORT_PCRE_ANCHORED         0x00040
#define SNORT_OVERRIDE_MATCH_LIMIT  0x00080 // Override default limits on match & match recursion

#define s_name "jwt"
#define mod_regex_name "regex"

#define JWT_EXPRESSION "/[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+/"

#define JWT_CLAIM_EXP (1 << 0)
#define JWT_CLAIM_SUB (1 << 1)
#define JWT_CLAIM_ISS (1 << 2)
#define JWT_CLAIM_IAT (1 << 3)
#define JWT_CLAIM_NBF (1 << 4)
#define JWT_HEADER_TYP (1 << 5)
#define JWT_HEADER_ALG (1 << 6)

static const Poco::Timestamp zero_ts = Poco::Timestamp(0);

struct JwtPcreData
{
    pcre* re;           /* compiled regex */
    pcre_extra* pe;     /* studied regex foo */
    bool free_pe;
    int options;        /* sp_pcre specific options (relative & inverse) */
    char* expression;
    uint32_t jwt_claims;
};

// we need to specify the vector length for our pcre_exec call.  we only care
// about the first vector, which if the match is successful will include the
// offset to the end of the full pattern match.  if we decide to store other
// matches, make *SURE* that this is a multiple of 3 as pcre requires it.

// this is a temporary value used during parsing and set in snort conf
// by verify; search uses the value in snort conf
static int s_ovector_max = -1;

static unsigned scratch_index;
static ScratchAllocator* scratcher = nullptr;

static THREAD_LOCAL ProfileStats jwtPcrePerfStats;

//-------------------------------------------------------------------------
// stats
//-------------------------------------------------------------------------

struct JwtStats
{
    PegCount jwt_rules;
#ifdef HAVE_HYPERSCAN
    PegCount jwt_to_hyper;
#endif
    PegCount jwt_pcre_native;
    PegCount jwt_missing_exp;
    PegCount jwt_missing_sub;
    PegCount jwt_missing_iss;
    PegCount jwt_missing_iat;
    PegCount jwt_missing_nbf;
    PegCount jwt_alg_is_none;
    PegCount jwt_typ_not_jwt;
    PegCount jwt_config_exp;
    PegCount jwt_config_sub;
    PegCount jwt_config_iss;
    PegCount jwt_config_iat;
    PegCount jwt_config_nbf;
    PegCount jwt_config_alg;
    PegCount jwt_config_typ;
};

const PegInfo jwt_pegs[] =
{
    { CountType::SUM, "jwt_rules", "total rules processed with jwt option" },
#ifdef HAVE_HYPERSCAN
     { CountType::SUM, "jwt_to_hyper", "total jwt rules by hyperscan engine" },
#endif
    { CountType::SUM, "jwt_pcre_native", "total jwt rules compiled by pcre engine" },
    { CountType::SUM, "jwt_missing_exp", "total jwts missing exp" },
    { CountType::SUM, "jwt_missing_sub", "total jwts missing sub" },
    { CountType::SUM, "jwt_missing_iss", "total jwts missing iss" },
    { CountType::SUM, "jwt_missing_iat", "total jwts missing iat" },
    { CountType::SUM, "jwt_missing_nbf", "total jwts missing nbf" },
    { CountType::SUM, "jwt_alg_is_none", "total unsecured jwts" },
    { CountType::SUM, "jwt_typ_not_jwt", "total jws not type JWT" },
    { CountType::SUM, "jwt_config_exp", "total jwt exp rules" },
    { CountType::SUM, "jwt_config_sub", "total jwts sub rules" },
    { CountType::SUM, "jwt_config_iss", "total jwt iss rules" },
    { CountType::SUM, "jwt_config_iat", "total jwt iat rules" },
    { CountType::SUM, "jwt_config_nbf", "total jwt nbf rules" },
    { CountType::SUM, "jwt_config_alg", "total jwt alg rules" },
    { CountType::SUM, "jwt_config_typ", "total jwt typ rules" },
    { CountType::END, nullptr, nullptr }
};

JwtStats jwt_stats;

//-------------------------------------------------------------------------
// implementation foo
//-------------------------------------------------------------------------

static void jwt_pcre_capture(
    const void* code, const void* extra)
{
    int tmp_ovector_size = 0;

    pcre_fullinfo((const pcre*)code, (const pcre_extra*)extra,
        PCRE_INFO_CAPTURECOUNT, &tmp_ovector_size);

    if (tmp_ovector_size > s_ovector_max)
        s_ovector_max = tmp_ovector_size;
}

static void jwt_pcre_check_anchored(JwtPcreData* pcre_data)
{
    int rc;
    unsigned long int options = 0;

    if ((pcre_data == nullptr) || (pcre_data->re == nullptr) || (pcre_data->pe == nullptr))
        return;

    rc = pcre_fullinfo(pcre_data->re, pcre_data->pe, PCRE_INFO_OPTIONS, (void*)&options);
    switch (rc)
    {
    /* pcre_fullinfo fails for the following:
     * PCRE_ERROR_NULL - the argument code was null
     *                   the argument where was null
     * PCRE_ERROR_BADMAGIC - the "magic number" was not found
     * PCRE_ERROR_BADOPTION - the value of what was invalid
     * so a failure here means we passed in bad values and we should
     * probably fatal error */

    case 0:
        /* This is the success code */
        break;

    case PCRE_ERROR_NULL:
        ParseError("pcre_fullinfo: code and/or where were null.");
        return;

    case PCRE_ERROR_BADMAGIC:
        ParseError("pcre_fullinfo: compiled code didn't have correct magic.");
        return;

    case PCRE_ERROR_BADOPTION:
        ParseError("pcre_fullinfo: option type is invalid.");
        return;

    default:
        ParseError("pcre_fullinfo: Unknown error code.");
        return;
    }

    if ((options & PCRE_ANCHORED) && !(options & PCRE_MULTILINE))
    {
        /* This means that this pcre rule option shouldn't be EvalStatus
         * even if any of it's relative children should fail to match.
         * It is anchored to the cursor set by the previous cursor setting
         * rule option */
        pcre_data->options |= SNORT_PCRE_ANCHORED;
    }
}

static void jwt_set_claims(JwtPcreData *pcre_data, const char *claims) {
    uint32_t jwt_claims = 0;

    if (strstr(claims, "exp")) {
        jwt_claims |= JWT_CLAIM_EXP;
        jwt_stats.jwt_config_exp++;
    }
    if (strstr(claims, "sub")) {
        jwt_claims |= JWT_CLAIM_SUB;
        jwt_stats.jwt_config_sub++;
    }
    if (strstr(claims, "iss")) {
        jwt_claims |= JWT_CLAIM_ISS;
        jwt_stats.jwt_config_iss++;
    }
    if (strstr(claims, "iat")) {
        jwt_claims |= JWT_CLAIM_IAT;
        jwt_stats.jwt_config_iat++;
    }
    if (strstr(claims, "nbf")) {
        jwt_claims |= JWT_CLAIM_NBF;
        jwt_stats.jwt_config_nbf++;
    }
    if (strstr(claims, "typ")) {
        jwt_claims |= JWT_HEADER_TYP;
        jwt_stats.jwt_config_typ++;
    }
    if (strstr(claims, "alg")) {
        jwt_claims |= JWT_HEADER_ALG;
        jwt_stats.jwt_config_alg++;
    }
    pcre_data->jwt_claims = jwt_claims;
}

static void jwt_parse(const SnortConfig* sc, const char* data, JwtPcreData* pcre_data)
{
    const char* error;
    char* re, * free_me;
    char* opts;
    char delimit = '/';
    int erroffset;
    int compile_flags = 0;

    if (data == nullptr || *data == '\0')
    {
        jwt_set_claims(pcre_data, "exp");
    } else {
        jwt_set_claims(pcre_data, data);
    }

    free_me = snort_strdup(JWT_EXPRESSION);
    re = free_me;

    /* get rid of starting and ending whitespace */
    while (isspace((int)re[strlen(re)-1]))
        re[strlen(re)-1] = '\0';
    while (isspace((int)*re))
        re++;

    if (*re == '!')
    {
        pcre_data->options |= SNORT_PCRE_INVERT;
        re++;
        while (isspace((int)*re))
            re++;
    }

    if ( *re == '"')
        re++;

    if ( re[strlen(re)-1] == '"' )
        re[strlen(re) - 1] = '\0';

    /* 'm//' or just '//' */

    if (*re == 'm')
    {
        re++;
        if (!*re)
            goto syntax;

        /* Space as a ending delimiter?  Uh, no. */
        if (isspace((int)*re))
            goto syntax;
        /* using R would be bad, as it triggers RE */
        if (*re == 'R')
            goto syntax;

        delimit = *re;
    }
    else if (*re != delimit)
        goto syntax;

    pcre_data->expression = snort_strdup(re);

    /* find ending delimiter, trim delimit chars */
    opts = strrchr(re, delimit);
    if (opts == nullptr)
        goto syntax;

    if (!((opts - re) > 1)) /* empty regex(m||) or missing delim not OK */
        goto syntax;

    re++;
    *opts++ = '\0';

    /* process any /regex/ismxR options */
    while (*opts != '\0')
    {
        switch (*opts)
        {
        case 'i':  compile_flags |= PCRE_CASELESS;            break;
        case 's':  compile_flags |= PCRE_DOTALL;              break;
        case 'm':  compile_flags |= PCRE_MULTILINE;           break;
        case 'x':  compile_flags |= PCRE_EXTENDED;            break;

        /*
         * these are pcre specific... don't work with perl
         */
        case 'A':  compile_flags |= PCRE_ANCHORED;            break;
        case 'E':  compile_flags |= PCRE_DOLLAR_ENDONLY;      break;
        case 'G':  compile_flags |= PCRE_UNGREEDY;            break;

        /*
         * these are snort specific don't work with pcre or perl
         */
        case 'R':  pcre_data->options |= SNORT_PCRE_RELATIVE; break;
        case 'O':
            if ( sc->pcre_override )
                pcre_data->options |= SNORT_OVERRIDE_MATCH_LIMIT;
            break;

        default:
            ParseError("unknown/extra pcre option encountered");
            return;
        }
        opts++;
    }

    /* now compile the re */
    pcre_data->re = pcre_compile(re, compile_flags, &error, &erroffset, nullptr);

    if (pcre_data->re == nullptr)
    {
        ParseError(": pcre compile of '%s' failed at offset "
            "%d : %s", re, erroffset, error);
        return;
    }

    /* now study it... */
    pcre_data->pe = pcre_study(pcre_data->re, PCRE_STUDY_FLAGS, &error);

    if (pcre_data->pe)
    {
        if ((sc->get_pcre_match_limit() != 0) &&
            !(pcre_data->options & SNORT_OVERRIDE_MATCH_LIMIT))
        {
            if ( !(pcre_data->pe->flags & PCRE_EXTRA_MATCH_LIMIT) )
                pcre_data->pe->flags |= PCRE_EXTRA_MATCH_LIMIT;

            pcre_data->pe->match_limit = sc->get_pcre_match_limit();
        }

        if ((sc->get_pcre_match_limit_recursion() != 0) &&
            !(pcre_data->options & SNORT_OVERRIDE_MATCH_LIMIT))
        {
            if ( !(pcre_data->pe->flags & PCRE_EXTRA_MATCH_LIMIT_RECURSION) )
                pcre_data->pe->flags |= PCRE_EXTRA_MATCH_LIMIT_RECURSION;

            pcre_data->pe->match_limit_recursion =
                sc->get_pcre_match_limit_recursion();
        }
    }
    else
    {
        if (!(pcre_data->options & SNORT_OVERRIDE_MATCH_LIMIT) &&
            ((sc->get_pcre_match_limit() != 0) ||
             (sc->get_pcre_match_limit_recursion() != 0)))
        {
            pcre_data->pe = (pcre_extra*)snort_calloc(sizeof(pcre_extra));
            pcre_data->free_pe = true;

            if (sc->get_pcre_match_limit() != 0)
            {
                pcre_data->pe->flags |= PCRE_EXTRA_MATCH_LIMIT;
                pcre_data->pe->match_limit = sc->get_pcre_match_limit();
            }

            if (sc->get_pcre_match_limit_recursion() != 0)
            {
                pcre_data->pe->flags |= PCRE_EXTRA_MATCH_LIMIT_RECURSION;
                pcre_data->pe->match_limit_recursion =
                    sc->get_pcre_match_limit_recursion();
            }
        }
    }

    if (error != nullptr)
    {
        ParseError("pcre study failed : %s", error);
        return;
    }

    jwt_pcre_capture(pcre_data->re, pcre_data->pe);
    jwt_pcre_check_anchored(pcre_data);

    snort_free(free_me);
    return;

syntax:
    snort_free(free_me);

    // ensure integrity from parse error to fatal error
    if ( !pcre_data->expression )
        pcre_data->expression = snort_strdup("");

    ParseError("unable to parse pcre %s", data);
}

/*
 * Perform a search of the PCRE data.
 * found_offset will be set to -1 when the find is unsuccessful OR the routine is inverted
 */
static bool pcre_search(
    Packet* p,
    const JwtPcreData* pcre_data,
    const uint8_t* buf,
    unsigned len,
    unsigned start_offset,
    int found_offset[])
{
    bool matched;

    found_offset[1] = -1;

    std::vector<void *> ss = p->context->conf->state[get_instance_id()];
    assert(ss[scratch_index]);

    int result = pcre_exec(
        pcre_data->re,  /* result of pcre_compile() */
        pcre_data->pe,  /* result of pcre_study()   */
        (const char*)buf, /* the subject string */
        len,            /* the length of the subject string */
        start_offset,   /* start at offset 0 in the subject */
        0,              /* options(handled at compile time */
        (int*)ss[scratch_index], /* vector for substring information */
        p->context->conf->pcre_ovector_size); /* number of elements in the vector */

    if (result >= 0)
    {
        matched = true;

        /* From the PCRE man page: When a match is successful, information
         * about captured substrings is returned in pairs of integers,
         * starting at the beginning of ovector, and continuing up to
         * two-thirds of its length at the most.  The first element of a
         * pair is set to the offset of the first character in a substring,
         * and the second is set to the offset of the first character after
         * the end of a substring. The first pair, ovector[0] and
         * ovector[1], identify the portion of the subject string matched
         * by the entire pattern.  The next pair is used for the first
         * capturing subpattern, and so on. The value returned by
         * pcre_exec() is the number of pairs that have been set. If there
         * are no capturing subpatterns, the return value from a successful
         * match is 1, indicating that just the first pair of offsets has
         * been set.
         *
         * In Snort's case, the ovector size only allows for the first pair
         * and a single int for scratch space.
         */

        found_offset[0] = ((int*)ss[scratch_index])[0];
        found_offset[1] = ((int*)ss[scratch_index])[1];
    }
    else if (result == PCRE_ERROR_NOMATCH)
    {
        matched = false;
    }
    else if (result == PCRE_ERROR_MATCHLIMIT)
    {
        pc.pcre_match_limit++;
        matched = false;
    }
    else if (result == PCRE_ERROR_RECURSIONLIMIT)
    {
        pc.pcre_recursion_limit++;
        matched = false;
    }
    else
    {
        pc.pcre_error++;
        return false;
    }

    /* invert sense of match */
    if (pcre_data->options & SNORT_PCRE_INVERT)
    {
        matched = !matched;
    }

    return matched;
}

//-------------------------------------------------------------------------
// class methods
//-------------------------------------------------------------------------

class JwtPcreOption : public IpsOption
{
public:
    JwtPcreOption(JwtPcreData* c) :
        IpsOption(s_name, RULE_OPTION_TYPE_CONTENT)
    { config = c; }

    ~JwtPcreOption() override;

    uint32_t hash() const override;
    bool operator==(const IpsOption&) const override;

    CursorActionType get_cursor_type() const override
    { return CAT_ADJUST; }

    bool is_relative() override
    { return (config->options & SNORT_PCRE_RELATIVE) != 0; }

    EvalStatus eval(Cursor&, Packet*) override;
    bool retry(Cursor&, const Cursor&) override;

    JwtPcreData* get_data()
    { return config; }

    void set_data(JwtPcreData* pcre)
    { config = pcre; }

private:
    JwtPcreData* config;
};

JwtPcreOption::~JwtPcreOption()
{
    if ( !config )
        return;

    if ( config->expression )
        snort_free(config->expression);

    if ( config->pe )
    {
        if ( config->free_pe )
            snort_free(config->pe);
        else
            pcre_release(config->pe);
    }

    if ( config->re )
        free(config->re);  // external allocation

    snort_free(config);
}

uint32_t JwtPcreOption::hash() const
{
    uint32_t a = 0, b = 0, c = 0;
    int expression_len = strlen(config->expression);
    int i, j;

    for (i=0,j=0; i<expression_len; i+=4)
    {
        uint32_t tmp = 0;
        int k = expression_len - i;

        if (k > 4)
            k=4;

        for (int l=0; l<k; l++)
        {
            tmp |= *(config->expression + i + l) << l*8;
        }

        switch (j)
        {
        case 0:
            a += tmp;
            break;
        case 1:
            b += tmp;
            break;
        case 2:
            c += tmp;
            break;
        }
        j++;

        if (j == 3)
        {
            mix(a,b,c);
            j=0;
        }
    }

    if (j != 0)
    {
        mix(a,b,c);
    }

    a += config->options;
    b += IpsOption::hash();

    mix(a,b,c);
    finalize(a,b,c);

    return c;
}

bool JwtPcreOption::operator==(const IpsOption& ips) const
{
    if ( !IpsOption::operator==(ips) )
        return false;

    const JwtPcreOption& rhs = (const JwtPcreOption&)ips;
    JwtPcreData* left = config;
    JwtPcreData* right = rhs.config;

    return left->jwt_claims == right->jwt_claims;
}

IpsOption::EvalStatus JwtPcreOption::eval(Cursor& c, Packet* p)
{
    RuleProfile profile(jwtPcrePerfStats);

    // short circuit this for testing pcre performance impact
    if ( p->context->conf->no_pcre() )
        return NO_MATCH;

    unsigned pos = c.get_delta();
    unsigned adj = 0;

    if ( pos > c.size() )
        return NO_MATCH;

    if ( !pos && is_relative() )
        adj = c.get_pos();

    int found_offset[2]; // where is the location of the pattern
    found_offset[1] = -1;

    if ( pcre_search(p, config, c.buffer()+adj, c.size()-adj, pos, found_offset) )
    {
        if ( found_offset[1] > 0 )
        {
            std::string jwt((char *)c.buffer() + adj + found_offset[0], found_offset[1] - found_offset[0]);
            Token token;
            try {
                token = Token(jwt);
            } catch (ParseException ex) {
                return NO_MATCH;
            }
            adj += found_offset[1];
            c.set_pos(adj);
            c.set_delta(adj);
            bool claims_ok = true;
            if ((config->jwt_claims & JWT_CLAIM_EXP) != 0 && token.getExpiration() == zero_ts) {
                jwt_stats.jwt_missing_exp++;
                claims_ok = false;
            }
            if ((config->jwt_claims & JWT_CLAIM_SUB) != 0 && token.getSubject().empty()) {
                jwt_stats.jwt_missing_sub++;
                claims_ok = false;
            }
            if ((config->jwt_claims & JWT_CLAIM_ISS) != 0 && token.getIssuer().empty()) {
                jwt_stats.jwt_missing_iss++;
                claims_ok = false;
            }
            if ((config->jwt_claims & JWT_CLAIM_IAT) != 0 && token.getIssuedAt() == zero_ts) {
                jwt_stats.jwt_missing_iat++;
                claims_ok = false;
            }
            if ((config->jwt_claims & JWT_CLAIM_NBF) != 0 && token.getNotBefore() == zero_ts) {
                jwt_stats.jwt_missing_nbf++;
                claims_ok = false;
            }
            if ((config->jwt_claims & JWT_HEADER_ALG) != 0 &&
                    (token.getAlgorithm().empty() || strcasecmp(token.getAlgorithm().c_str(), "none") == 0)) {
                jwt_stats.jwt_alg_is_none++;
                claims_ok = false;
            }
            if ((config->jwt_claims & JWT_HEADER_TYP) != 0 &&
                    (token.getType().empty() || token.getType() != "JWT")) {
                jwt_stats.jwt_typ_not_jwt++;
                claims_ok = false;
            }
            if (claims_ok) {
                return NO_MATCH;
            }
        }
        return MATCH;
    }

    return NO_MATCH;
}

// we always advance by found_offset so no adjustments to cursor are done
// here; note also that this means relative pcre matches on overlapping
// patterns won't work.  given the test pattern "ABABACD":
//
// ( sid:1; content:"ABA"; content:"C"; within:1; )
// ( sid:2; pcre:"/ABA/"; content:"C"; within:1; )
//
// sid 1 will fire but sid 2 will NOT.  this example is easily fixed by
// using content, but more advanced pcre won't work for the relative /
// overlap case.

bool JwtPcreOption::retry(Cursor&, const Cursor&)
{
    if ((config->options & (SNORT_PCRE_INVERT | SNORT_PCRE_ANCHORED)))
    {
        return false; // no go
    }
    return true;  // continue
}

//-------------------------------------------------------------------------
// module
//-------------------------------------------------------------------------

static const Parameter s_params[] =
{
    { "~re", Parameter::PT_STRING, nullptr, nullptr,
      "Snort regular expression" },

    { nullptr, Parameter::PT_MAX, nullptr, nullptr, nullptr }
};

#define s_help \
    "rule option for matching jwt payload data"

class JwtPcreModule : public Module
{
public:
    JwtPcreModule() : Module(s_name, s_help, s_params)
    {
        data = nullptr;
        scratcher = new SimpleScratchAllocator(scratch_setup, scratch_cleanup);
        scratch_index = scratcher->get_id();
    }

    ~JwtPcreModule() override
    {
        delete data;
        delete scratcher;
    }

#ifdef HAVE_HYPERSCAN
    bool begin(const char*, int, SnortConfig*) override;
#endif
    bool set(const char*, Value&, SnortConfig*) override;
    bool end(const char*, int, SnortConfig*) override;

    ProfileStats* get_profile() const override
    { return &jwtPcrePerfStats; }

    const PegInfo* get_pegs() const override;
    PegCount* get_counts() const override;

    JwtPcreData* get_data();

    Usage get_usage() const override
    { return DETECT; }

    Module* get_mod_regex() const
    { return mod_regex; }

private:
    JwtPcreData* data;
    Module* mod_regex = nullptr;
    std::string claims;

    static bool scratch_setup(SnortConfig*);
    static void scratch_cleanup(SnortConfig*);
};

JwtPcreData* JwtPcreModule::get_data()
{
    JwtPcreData* tmp = data;
    data = nullptr;
    return tmp;
}

const PegInfo* JwtPcreModule::get_pegs() const
{ return jwt_pegs; }

PegCount* JwtPcreModule::get_counts() const
{ return (PegCount*)&jwt_stats; }

#ifdef HAVE_HYPERSCAN
bool JwtPcreModule::begin(const char* name, int v, SnortConfig* sc)
{
    if ( sc->pcre_to_regex )
    {
        if ( !mod_regex )
            mod_regex = ModuleManager::get_module(mod_regex_name);

        if( mod_regex )
            mod_regex = mod_regex->begin(name, v, sc) ? mod_regex : nullptr;
    }
    return true;
}
#endif

bool JwtPcreModule::set(const char* name, Value& v, SnortConfig* sc)
{
    assert(v.is("~re"));
    claims = v.get_string();

    if( mod_regex )
        mod_regex = mod_regex->set(name, v, sc) ? mod_regex : nullptr;

    return true;
}

bool JwtPcreModule::end(const char* name, int v, SnortConfig* sc)
{
    if( mod_regex )
        mod_regex = mod_regex->end(name, v, sc) ? mod_regex : nullptr;

    if ( !mod_regex )
    {
        data = (JwtPcreData*)snort_calloc(sizeof(*data));
        jwt_parse(sc, claims.c_str(), data);
    }

    return true;
}

bool JwtPcreModule::scratch_setup(SnortConfig* sc)
{
    if ( s_ovector_max < 0 )
        return false;

    // The pcre_fullinfo() function can be used to find out how many
    // capturing subpatterns there are in a compiled pattern. The
    // smallest size for ovector that will allow for n captured
    // substrings, in addition to the offsets of the substring matched
    // by the whole pattern is 3(n+1).

    sc->pcre_ovector_size = 3 * (s_ovector_max + 1);
    s_ovector_max = -1;

    for ( unsigned i = 0; i < sc->num_slots; ++i )
    {
        std::vector<void *>& ss = sc->state[i];
        ss[scratch_index] = snort_calloc(sc->pcre_ovector_size, sizeof(int));
    }
    return true;
}

void JwtPcreModule::scratch_cleanup(SnortConfig* sc)
{
    for ( unsigned i = 0; i < sc->num_slots; ++i )
    {
        std::vector<void *>& ss = sc->state[i];
        snort_free(ss[scratch_index]);
        ss[scratch_index] = nullptr;
    }
}

//-------------------------------------------------------------------------
// api methods
//-------------------------------------------------------------------------

static Module* mod_ctor()
{ return new JwtPcreModule; }

static void mod_dtor(Module* m)
{ delete m; }

static IpsOption* pcre_ctor(Module* p, OptTreeNode* otn)
{
    jwt_stats.jwt_rules++;
    JwtPcreModule* m = (JwtPcreModule*)p;

#ifdef HAVE_HYPERSCAN
    Module* mod_regex = m->get_mod_regex();
    if ( mod_regex )
    {
        jwt_stats.jwt_to_hyper++;
        const IpsApi* opt_api = IpsManager::get_option_api(mod_regex_name);
        return opt_api->ctor(mod_regex, otn);
    }
    else
#else
    UNUSED(otn);
#endif
    {
        jwt_stats.jwt_pcre_native++;
        JwtPcreData* d = m->get_data();
        return new JwtPcreOption(d);
    }
}

static void pcre_dtor(IpsOption* p)
{ delete p; }

static const IpsApi jwt_api =
{
    {
        PT_IPS_OPTION,
        sizeof(IpsApi),
        IPSAPI_VERSION,
        0,
        API_RESERVED,
        API_OPTIONS,
        s_name,
        s_help,
        mod_ctor,
        mod_dtor
    },
    OPT_TYPE_DETECTION,
    0, 0,
    nullptr,
    nullptr,
    nullptr,
    nullptr,
    pcre_ctor,
    pcre_dtor,
    nullptr
};

#ifdef BUILDING_SO
SO_PUBLIC const BaseApi* snort_plugins[] =
#else
const BaseApi* ips_jwt[] =
#endif
{
    &jwt_api.base,
    nullptr
};
