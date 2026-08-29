// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// wave.cpp — FPC threshold voting + confidence accumulation. Faithful port of
// luxfi/consensus protocol/wave.Tick (with protocol/focus's β counter).

#include "lux/consensus/wave.hpp"

#include <stdexcept>

namespace lux::consensus {

WaveConfig WaveConfig::feasible(std::uint32_t n) noexcept {
    WaveConfig cfg;
    cfg.k = n < kMinBFTCommittee ? kMinBFTCommittee : n;  // never a dead large set
    // The count itself, from threshold.hpp — Go's equal-stake strict-⅔ rule.
    // Carried as the count, so there is no ratio to recover it from and nothing
    // to round.
    cfg.threshold = equal_stake_supermajority(cfg.k);
    cfg.beta  = kFeasibleBeta;
    return cfg;
}

Wave::Wave(WaveConfig cfg) : cfg_(cfg) {
    if (cfg_.k == 0)
        throw std::invalid_argument("wave: k (committee size) is zero");
    if (cfg_.beta == 0)
        throw std::invalid_argument("wave: beta (confidence threshold) is zero");
    if (cfg_.threshold == 0 || cfg_.threshold > cfg_.k)
        throw std::invalid_argument("wave: threshold must be in [1, k]");

    threshold_ = static_cast<int>(cfg_.threshold);
    // A supermajority threshold must exceed half the committee, else both ACCEPT
    // and REJECT could clear it in one round. Fail closed on an unsafe config.
    if (threshold_ * 2 <= static_cast<int>(cfg_.k))
        throw std::invalid_argument("wave: threshold is not a majority of k");
}

Decision Wave::record_round(const Item & item, std::uint32_t yes, std::uint32_t total) {
    State& st = states_[item];
    if (st.decided) return st.result;      // latched — never reopen a decision
    // Clamp the tally to the committee size: with total > k the constructor's
    // majority guard (threshold·2 > k) no longer prevents BOTH sides clearing the
    // threshold in one round (red L5). A correct sampler never exceeds k; clamping
    // makes the "exactly one side can be strong" invariant hold unconditionally.
    if (total > cfg_.k) total = cfg_.k;
    if (total == 0) return st.result;      // no responses this round; no state change
    if (yes > total) yes = total;          // defensive: a tally cannot exceed its total

    const bool yes_strong = static_cast<int>(yes) >= threshold_;
    const bool no_strong = static_cast<int>(total - yes) >= threshold_;

    if (yes_strong) {
        if (st.have_pref && st.pref)
            ++st.count;                    // consecutive confirmation of Accept
        else
            st.count = 1;                  // new/ switched preference → restart at 1
        st.pref = true;
        st.have_pref = true;
    } else if (no_strong) {
        if (st.have_pref && !st.pref)
            ++st.count;                    // consecutive confirmation of Reject
        else
            st.count = 1;
        st.pref = false;
        st.have_pref = true;
    } else {
        st.count = 0;                      // INCONCLUSIVE → reset (the anti-toy rule)
    }

    if (st.count >= cfg_.beta) {
        st.decided = true;
        st.result = st.pref ? Decision::Accept : Decision::Reject;
    }
    return st.result;
}

Decision Wave::decision(const Item & item) const {
    const auto it = states_.find(item);
    return it == states_.end() ? Decision::Undecided : it->second.result;
}

std::uint32_t Wave::confidence(const Item & item) const {
    const auto it = states_.find(item);
    return it == states_.end() ? 0 : it->second.count;
}

}  // namespace lux::consensus
