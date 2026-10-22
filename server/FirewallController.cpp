/*
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <algorithm>
#include <set>

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cstdint>

#define LOG_TAG "FirewallController"
#define LOG_NDEBUG 0

#include <android-base/file.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <log/log.h>

#include "Controllers.h"
#include "FirewallController.h"
#include "NetdConstants.h"
#include "bpf/BpfUtils.h"

using android::base::Join;
using android::base::StringAppendF;
using android::base::StringPrintf;

namespace android {
namespace net {

auto FirewallController::execIptablesRestore = ::execIptablesRestore;

const char* FirewallController::TABLE = "filter";

const char* FirewallController::LOCAL_INPUT = "fw_INPUT";
const char* FirewallController::LOCAL_OUTPUT = "fw_OUTPUT";
const char* FirewallController::LOCAL_FORWARD = "fw_FORWARD";

// ICMPv6 types that are required for any form of IPv6 connectivity to work. Note that because the
// fw_dozable chain is called from both INPUT and OUTPUT, this includes both packets that we need
// to be able to send (e.g., RS, NS), and packets that we need to receive (e.g., RA, NA).
const char* FirewallController::ICMPV6_TYPES[] = {
    "packet-too-big",
    "router-solicitation",
    "router-advertisement",
    "neighbour-solicitation",
    "neighbour-advertisement",
    "redirect",
};

FirewallController::FirewallController(void) {
    // If no rules are set, it's in DENYLIST mode
    mFirewallType = DENYLIST;
    mIfaceRules = {};
}

int FirewallController::setupIptablesHooks(void) {
    if (int ret = flushRules()) return ret;
    if (!android::base::GetBoolProperty("ro.kernel.ebpf.supported", true)) {
        return setupLegacyUidChains();
    }
    return 0;
}

int FirewallController::setFirewallType(FirewallType ftype) {
    int res = 0;
    if (mFirewallType != ftype) {
        // flush any existing rules
        resetFirewall();

        if (ftype == ALLOWLIST) {
            // create default rule to drop all traffic
            std::string command =
                "*filter\n"
                "-A fw_INPUT -j DROP\n"
                "-A fw_OUTPUT -j REJECT\n"
                "-A fw_FORWARD -j REJECT\n"
                "COMMIT\n";
            res = execIptablesRestore(V4V6, command.c_str());
        }

        // Set this after calling disableFirewall(), since it defaults to ALLOWLIST there
        mFirewallType = ftype;
    }
    return res ? -EREMOTEIO : 0;
}

int FirewallController::flushRules() {
    std::string command =
            "*filter\n"
            ":fw_INPUT -\n"
            ":fw_OUTPUT -\n"
            ":fw_FORWARD -\n"
            "-6 -A fw_OUTPUT ! -o lo -s ::1 -j DROP\n"
            "COMMIT\n";

    if (execIptablesRestore(V4V6, command.c_str()) != 0) return -EREMOTEIO;
    // Flushing fw_INPUT and fw_OUTPUT drops the jumps to enabled child chains.
    for (const auto& name : mEnabledChains) {
        if (int ret = linkChildChain(name, "-A")) return ret;
    }
    return 0;
}

int FirewallController::resetFirewall(void) {
    mFirewallType = ALLOWLIST;
    mIfaceRules.clear();
    return flushRules();
}

int FirewallController::isFirewallEnabled(void) {
    // TODO: verify that rules are still in place near top
    return -1;
}

int FirewallController::setInterfaceRule(const char* iface, FirewallRule rule) {
    if (mFirewallType == DENYLIST) {
        // Unsupported in DENYLIST mode
        return -EINVAL;
    }

    if (!isIfaceName(iface)) {
        errno = ENOENT;
        return -ENOENT;
    }

    // Only delete rules if we actually added them, because otherwise our iptables-restore
    // processes will terminate with "no such rule" errors and cause latency penalties while we
    // spin up new ones.
    const char* op;
    if (rule == ALLOW && mIfaceRules.find(iface) == mIfaceRules.end()) {
        op = "-I";
        mIfaceRules.insert(iface);
    } else if (rule == DENY && mIfaceRules.find(iface) != mIfaceRules.end()) {
        op = "-D";
        mIfaceRules.erase(iface);
    } else {
        return 0;
    }

    std::string command = Join(std::vector<std::string> {
        "*filter",
        StringPrintf("%s fw_INPUT -i %s -j RETURN", op, iface),
        StringPrintf("%s fw_OUTPUT -o %s -j RETURN", op, iface),
        "COMMIT\n"
    }, "\n");
    return (execIptablesRestore(V4V6, command) == 0) ? 0 : -EREMOTEIO;
}

/* static */
std::string FirewallController::makeCriticalCommands(IptablesTarget target, const char* chainName) {
    // Allow ICMPv6 packets necessary to make IPv6 connectivity work. http://b/23158230 .
    std::string commands;
    if (target == V6) {
        for (size_t i = 0; i < ARRAY_SIZE(ICMPV6_TYPES); i++) {
            StringAppendF(&commands, "-A %s -p icmpv6 --icmpv6-type %s -j RETURN\n",
                   chainName, ICMPV6_TYPES[i]);
        }
    }
    return commands;
}

namespace {

struct UidChain {
    int32_t id;
    const char* name;
    bool isAllowlist;
};

// INetd and ConnectivityManager chain numbers, and the chains Android 11 used for them.
constexpr UidChain UID_CHAINS[] = {
        {1, "fw_dozable", true},           {2, "fw_standby", false},
        {3, "fw_powersave", true},         {4, "fw_restricted", true},
        {5, "fw_low_power_standby", true}, {7, "fw_oem_deny_1", false},
        {8, "fw_oem_deny_2", false},       {9, "fw_oem_deny_3", false},
};

const UidChain* findChain(int32_t id) {
    for (const auto& chain : UID_CHAINS) {
        if (chain.id == id) return &chain;
    }
    return nullptr;
}

const UidChain* findChain(const std::string& name) {
    for (const auto& chain : UID_CHAINS) {
        if (name == chain.name) return &chain;
    }
    return nullptr;
}

std::vector<std::pair<int32_t, int32_t>> uidRanges(std::vector<int32_t> uids) {
    std::sort(uids.begin(), uids.end());
    std::vector<std::pair<int32_t, int32_t>> ranges;
    for (const auto uid : uids) {
        if (!ranges.empty() && uid <= ranges.back().second + 1) {
            ranges.back().second = std::max(ranges.back().second, uid);
        } else {
            ranges.emplace_back(uid, uid);
        }
    }
    return ranges;
}

const char* uidRuleTarget(bool isAllowlist) {
    return isAllowlist ? "RETURN" : "DROP";
}

}  // namespace

int FirewallController::setupLegacyUidChains() {
    for (const auto& chain : UID_CHAINS) {
        if (int ret = replaceUidChain(chain.name, chain.isAllowlist, {})) return ret;
    }
    return 0;
}

// Allowlist chains let system UIDs, TCP resets and the ICMPv6 needed for IPv6 through, then
// drop everything else. Denylist chains drop the listed UIDs. The owner match comes from
// xt_qtaguid, which also matches incoming packets of local sockets.
int FirewallController::replaceUidChain(const std::string& name, bool isAllowlist,
                                        const std::vector<int32_t>& uids) {
    const UidChain* chain = findChain(name);
    if (!chain || chain->isAllowlist != isAllowlist) return -EINVAL;
    const auto commandsFor = [chain, isAllowlist](IptablesTarget target,
                                                  const std::vector<int32_t>& chainUids) {
        std::string commands = StringPrintf("*filter\n:%s -\n", chain->name);
        if (isAllowlist) {
            StringAppendF(&commands, "-A %s -m owner --uid-owner 0-9999 -j RETURN\n", chain->name);
            StringAppendF(&commands, "-A %s -p tcp --tcp-flags RST RST -j RETURN\n", chain->name);
            commands += makeCriticalCommands(target, chain->name);
        }
        // Every packet walks the chain, so consecutive UIDs share one range rule.
        for (const auto& [first, last] : uidRanges(chainUids)) {
            StringAppendF(&commands, "-A %s -m owner --uid-owner %d-%d -j %s\n", chain->name,
                          first, last, uidRuleTarget(isAllowlist));
        }
        StringAppendF(&commands, "-A %s -j %s\nCOMMIT\n", chain->name,
                      isAllowlist ? "DROP" : "RETURN");
        return commands;
    };
    if (execIptablesRestore(V4, commandsFor(V4, uids)) != 0) return -EREMOTEIO;
    if (execIptablesRestore(V6, commandsFor(V6, uids)) != 0) {
        // Keep both families on the same rules: put IPv4 back to the previous UID set.
        const auto& previous = mUidRules[chain->name];
        execIptablesRestore(V4, commandsFor(V4, std::vector<int32_t>(previous.begin(),
                                                                     previous.end())));
        return -EREMOTEIO;
    }
    mUidRules[chain->name] = std::set<int32_t>(uids.begin(), uids.end());
    return 0;
}

int FirewallController::setUidRule(int32_t chainId, int32_t uid, FirewallRule rule) {
    const UidChain* chain = findChain(chainId);
    if (!chain) return -EINVAL;
    // Allowlists list allowed UIDs and denylists denied ones.
    const bool wantListed = (rule == ALLOW) == chain->isAllowlist;
    std::set<int32_t> listed = mUidRules[chain->name];
    if (wantListed == (listed.count(uid) > 0)) return 0;
    if (wantListed) {
        listed.insert(uid);
    } else {
        listed.erase(uid);
    }
    // A UID may sit inside a range rule, so the chain is rebuilt rather than edited.
    return replaceUidChain(chain->name, chain->isAllowlist,
                           std::vector<int32_t>(listed.begin(), listed.end()));
}

int FirewallController::linkChildChain(const std::string& name, const char* op) {
    const std::string command =
            StringPrintf("*filter\n%s fw_INPUT -j %s\n%s fw_OUTPUT -j %s\nCOMMIT\n", op,
                         name.c_str(), op, name.c_str());
    return (execIptablesRestore(V4V6, command) == 0) ? 0 : -EREMOTEIO;
}

int FirewallController::enableChildChain(int32_t chainId, bool enable) {
    const UidChain* chain = findChain(chainId);
    if (!chain) return -EINVAL;
    if (enable == (mEnabledChains.count(chain->name) > 0)) return 0;
    if (int ret = linkChildChain(chain->name, enable ? "-A" : "-D")) return ret;
    if (enable) {
        mEnabledChains.insert(chain->name);
    } else {
        mEnabledChains.erase(chain->name);
    }
    return 0;
}

}  // namespace net
}  // namespace android
