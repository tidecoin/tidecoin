// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/feefrac.h>

#include <arith_uint256.h>
#include <util/check.h>

#include <array>
#include <cstddef>

std::partial_ordering CompareChunks(std::span<const FeeFrac> chunks0, std::span<const FeeFrac> chunks1)
{
    // Use the existing portable unsigned arithmetic as two's-complement signed
    // arithmetic for diagram fees. Positive chunk sizes bound the number of
    // chunks below 2^31, so fee sums need at most 94 magnitude bits, differences
    // 95, and cross products 126. They cannot approach the 256-bit sign boundary.
    // Flipping that sign bit maps signed order to unsigned order.
    const arith_uint256 sign_bit{arith_uint256{1} << 255};
    const auto compare_fees = [&](const arith_uint256& a, const arith_uint256& b) {
        return (a ^ sign_bit) <=> (b ^ sign_bit);
    };
    struct Point {
        arith_uint256 fee;
        int32_t size{0};
    };
    /** Array to allow indexed access to input diagrams. */
    const std::array<std::span<const FeeFrac>, 2> chunk = {chunks0, chunks1};
    /** How many elements we have processed in each input. */
    size_t next_index[2] = {0, 0};
    /** Accumulated fee/sizes in diagrams, up to next_index[i] - 1. */
    Point accum[2];
    /** Whether the corresponding input is strictly better than the other at least in one place. */
    bool better_somewhere[2] = {false, false};
    /** Get the first unprocessed point in diagram number dia. */
    const auto next_point = [&](int dia) {
        const auto& next = chunk[dia][next_index[dia]];
        Point point{accum[dia]};
        if (next.fee < 0) {
            // Unsigned subtraction also handles INT64_MIN without negating it.
            point.fee -= uint64_t{0} - uint64_t(next.fee);
        } else {
            point.fee += uint64_t(next.fee);
        }
        point.size += next.size;
        return point;
    };
    /** Get the last processed point in diagram number dia. */
    const auto prev_point = [&](int dia) -> const Point& { return accum[dia]; };
    /** Move to the next point in diagram number dia. */
    const auto advance = [&](int dia, const Point& point) { accum[dia] = point; ++next_index[dia]; };

    do {
        bool done_0 = next_index[0] == chunk[0].size();
        bool done_1 = next_index[1] == chunk[1].size();
        if (done_0 && done_1) break;

        // Determine which diagram has the first unprocessed point. If a single side is finished, use the
        // other one. Only up to one can be done due to check above.
        const int unproc_side = (done_0 || done_1) ? done_0 :
            accum[0].size + chunk[0][next_index[0]].size > accum[1].size + chunk[1][next_index[1]].size;

        // Let `P` be the next point on diagram unproc_side, and `A` and `B` the previous and next points
        // on the other diagram. We want to know if P lies above or below the line AB. To determine this, we
        // compare the slopes of line AB and line AP using wide cross products to preserve exact ordering.
        const Point& point_p = next_point(unproc_side);
        const Point& point_a = prev_point(!unproc_side);

        const arith_uint256 fee_ap{point_p.fee - point_a.fee};
        const int32_t size_ap{point_p.size - point_a.size};
        Assume(size_ap > 0);
        auto cmp = std::strong_ordering::equivalent;
        if (done_0 || done_1) {
            // If a single side has no points left, act as if AB has slope tail_feerate(of 0).
            Assume(!(done_0 && done_1));
            cmp = compare_fees(fee_ap, arith_uint256{0});
        } else {
            // If both sides have points left, compute B, and the slope of AB explicitly.
            const Point& point_b = next_point(!unproc_side);
            const arith_uint256 fee_ab{point_b.fee - point_a.fee};
            const int32_t size_ab{point_b.size - point_a.size};
            Assume(size_ab >= size_ap);
            cmp = compare_fees(fee_ap * uint32_t(size_ab), fee_ab * uint32_t(size_ap));

            // If B and P have the same size, B can be marked as processed (in addition to P, see
            // below), as we've already performed a comparison at this size.
            if (point_b.size == point_p.size) advance(!unproc_side, point_b);
        }
        // If P lies above AB, unproc_side is better in P. If P lies below AB, then !unproc_side is
        // better in P.
        if (std::is_gt(cmp)) better_somewhere[unproc_side] = true;
        if (std::is_lt(cmp)) better_somewhere[!unproc_side] = true;
        advance(unproc_side, point_p);

        // If both diagrams are better somewhere, they are incomparable.
        if (better_somewhere[0] && better_somewhere[1]) return std::partial_ordering::unordered;
    } while(true);

    // Otherwise compare the better_somewhere values.
    return better_somewhere[0] <=> better_somewhere[1];
}
