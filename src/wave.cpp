// Copyright (C) 2026, Lux Industries, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// wave.cpp — FPC threshold voting + confidence accumulation. Faithful port of
// luxfi/consensus protocol/wave.Tick (with protocol/focus's β counter).

#include "lux/consensus2/wave.hpp"

#include <stdexcept>

namespace lux::consensus2 {

WaveConfig WaveConfig::feasible(std::uint32_t n) noexcept {
    WaveConfig cfg;
    cfg.k = n < kMinBFTCommittee ? kMinBFTCommittee : n;  // never a dead large set
    // α = the equal-stake strict-⅔ count, expressed as a ratio of K. The count
    // itself is threshold.hpp's; ceil(K·α) recovers it exactly.
    cfg.alpha = static_cast<double>(equal_stake_supermajority(cfg.k)) /
                static_cast<double>(cfg.k);
    cfg.beta  = kFeasibleBeta;
    return cfg;
}

Wave::Wave(WaveConfig cfg) : cfg_(cfg) {
    if (cfg_.k == 0)
        throw std::invalid_argument("wave: k (committee size) is zero");
    if (cfg_.beta == 0)
        throw std::invalid_argument("wave: beta (confidence threshold) is zero");
    if (!(cfg_.alpha > 0.0) || cfg_.alpha > 1.0)
        throw std::invalid_argument("wave: alpha must be in (0, 1]");

    threshold_ = alpha_threshold(cfg_.k, cfg_.alpha);
    // A supermajority threshold must exceed half the committee, else both ACCEPT
    // and REJECT could clear it in one round. Fail closed on an unsafe config.
    if (threshold_ * 2 <= static_cast<int>(cfg_.k))
        throw std::invalid_argument("wave: alpha too low — threshold not a majority of k");
    if (threshold_ > static_cast<int>(cfg_.k))
        threshold_ = static_cast<int>(cfg_.k);
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

}  // namespace lux::consensus2
