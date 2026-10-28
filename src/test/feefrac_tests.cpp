// Copyright (c) 2024-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <util/feefrac.h>
#include <random.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <limits>
#include <vector>

BOOST_AUTO_TEST_SUITE(feefrac_tests)

BOOST_AUTO_TEST_CASE(diagram_large_fees)
{
    constexpr int64_t max{std::numeric_limits<int64_t>::max()};
    constexpr int64_t min{std::numeric_limits<int64_t>::min()};
    const auto check = [](std::vector<FeeFrac> a, std::vector<FeeFrac> b, std::partial_ordering expected) {
        BOOST_CHECK(CompareChunks(a, b) == expected);
        BOOST_CHECK(CompareChunks(b, a) == (0 <=> expected));
        BOOST_CHECK(std::is_eq(CompareChunks(a, a)));
        BOOST_CHECK(std::is_eq(CompareChunks(b, b)));
    };
    // Cumulative sums and differences can overflow independently. Tail checks
    // must also handle negative totals and INT64_MIN without signed negation.
    check({{max, 1}, {max, 1}}, {{max, 2}}, std::partial_ordering::greater);
    check({{min, 1}, {min, 1}}, {{min, 2}}, std::partial_ordering::less);
    check({{max, 2}}, {{min, 1}}, std::partial_ordering::greater);
    check({{min, 2}}, {{max, 1}}, std::partial_ordering::less);
    check({{max, 1}, {min, 1}}, {{0, 2}}, std::partial_ordering::unordered);
    check({{min, 1}, {min, 1}}, {}, std::partial_ordering::less);

    // Seventy affected clusters can contribute 63 surviving ancestors each.
    // Their common prefix exceeds int64_t even with MAX_MONEY-sized fees.
    std::vector<FeeFrac> old_chunks(70, FeeFrac{63 * int64_t{2'100'000'000'000'000}, 63'000});
    auto new_chunks{old_chunks};
    old_chunks.insert(old_chunks.end(), 70, FeeFrac{1000, 1000});
    new_chunks.emplace_back(2'100'000'000'000'000, 70'000);
    check(new_chunks, old_chunks, std::partial_ordering::greater);

    // Multiplying every fee by a positive factor must preserve diagram order,
    // including equal/incomparable diagrams and those with negative chunks.
    FastRandomContext rng{true};
    for (int trial = 0; trial < 1000; ++trial) {
        std::vector<FeeFrac> a, b;
        for (auto* diagram : {&a, &b}) {
            const auto count{rng.randrange(32)};
            for (int i = 0; i < count; ++i) {
                diagram->emplace_back(int64_t(rng.randrange(31)) - 15, int32_t(1 + rng.randrange(1000)));
            }
            std::ranges::sort(*diagram, std::greater<ByRatio<FeeFrac>>{});
        }
        const auto expected{CompareChunks(a, b)};
        for (auto* diagram : {&a, &b}) {
            for (auto& chunk : *diagram) chunk.fee *= int64_t{1} << 59;
        }
        check(a, b, expected);
    }
}

BOOST_AUTO_TEST_CASE(feefrac_operators)
{
    FeeFrac p1{1000, 100}, p2{500, 300};
    FeeFrac sum{1500, 400};
    FeeFrac diff{500, -200};
    FeeFrac empty{0, 0};
    FeeFrac zero_fee{0, 1}; // zero-fee allowed

    BOOST_CHECK_EQUAL(zero_fee.EvaluateFeeDown(0), 0);
    BOOST_CHECK_EQUAL(zero_fee.EvaluateFeeDown(1), 0);
    BOOST_CHECK_EQUAL(zero_fee.EvaluateFeeDown(1000000), 0);
    BOOST_CHECK_EQUAL(zero_fee.EvaluateFeeDown(0x7fffffff), 0);
    BOOST_CHECK_EQUAL(zero_fee.EvaluateFeeUp(0), 0);
    BOOST_CHECK_EQUAL(zero_fee.EvaluateFeeUp(1), 0);
    BOOST_CHECK_EQUAL(zero_fee.EvaluateFeeUp(1000000), 0);
    BOOST_CHECK_EQUAL(zero_fee.EvaluateFeeUp(0x7fffffff), 0);

    BOOST_CHECK_EQUAL(p1.EvaluateFeeDown(0), 0);
    BOOST_CHECK_EQUAL(p1.EvaluateFeeDown(1), 10);
    BOOST_CHECK_EQUAL(p1.EvaluateFeeDown(100000000), 1000000000);
    BOOST_CHECK_EQUAL(p1.EvaluateFeeDown(0x7fffffff), int64_t(0x7fffffff) * 10);
    BOOST_CHECK_EQUAL(p1.EvaluateFeeUp(0), 0);
    BOOST_CHECK_EQUAL(p1.EvaluateFeeUp(1), 10);
    BOOST_CHECK_EQUAL(p1.EvaluateFeeUp(100000000), 1000000000);
    BOOST_CHECK_EQUAL(p1.EvaluateFeeUp(0x7fffffff), int64_t(0x7fffffff) * 10);

    FeeFrac neg{-1001, 100};
    BOOST_CHECK_EQUAL(neg.EvaluateFeeDown(0), 0);
    BOOST_CHECK_EQUAL(neg.EvaluateFeeDown(1), -11);
    BOOST_CHECK_EQUAL(neg.EvaluateFeeDown(2), -21);
    BOOST_CHECK_EQUAL(neg.EvaluateFeeDown(3), -31);
    BOOST_CHECK_EQUAL(neg.EvaluateFeeDown(100), -1001);
    BOOST_CHECK_EQUAL(neg.EvaluateFeeDown(101), -1012);
    BOOST_CHECK_EQUAL(neg.EvaluateFeeDown(100000000), -1001000000);
    BOOST_CHECK_EQUAL(neg.EvaluateFeeDown(100000001), -1001000011);
    BOOST_CHECK_EQUAL(neg.EvaluateFeeDown(0x7fffffff), -21496311307);
    BOOST_CHECK_EQUAL(neg.EvaluateFeeUp(0), 0);
    BOOST_CHECK_EQUAL(neg.EvaluateFeeUp(1), -10);
    BOOST_CHECK_EQUAL(neg.EvaluateFeeUp(2), -20);
    BOOST_CHECK_EQUAL(neg.EvaluateFeeUp(3), -30);
    BOOST_CHECK_EQUAL(neg.EvaluateFeeUp(100), -1001);
    BOOST_CHECK_EQUAL(neg.EvaluateFeeUp(101), -1011);
    BOOST_CHECK_EQUAL(neg.EvaluateFeeUp(100000000), -1001000000);
    BOOST_CHECK_EQUAL(neg.EvaluateFeeUp(100000001), -1001000010);
    BOOST_CHECK_EQUAL(neg.EvaluateFeeUp(0x7fffffff), -21496311306);

    BOOST_CHECK(empty == FeeFrac{}); // same as no-args

    BOOST_CHECK(p1 == p1);
    BOOST_CHECK(p1 + p2 == sum);
    BOOST_CHECK(p1 - p2 == diff);

    FeeFrac p3{2000, 200};
    BOOST_CHECK(p1 != p3); // feefracs only equal if both fee and size are same
    BOOST_CHECK(p2 != p3);

    FeeFrac p4{3000, 300};
    BOOST_CHECK(p1 == p4-p3);
    BOOST_CHECK(p1 + p3 == p4);

    // Fee-rate comparison
    BOOST_CHECK(ByRatioNegSize{p1} > ByRatioNegSize{p2});
    BOOST_CHECK(ByRatioNegSize{p1} >= ByRatioNegSize{p2});
    BOOST_CHECK(ByRatioNegSize{p1} >= ByRatioNegSize{p4-p3});
    BOOST_CHECK(!(ByRatio{p1} > ByRatio{p3})); // not strictly better
    BOOST_CHECK(ByRatio{p1} > ByRatio{p2}); // strictly greater feerate

    BOOST_CHECK(ByRatioNegSize{p2} < ByRatioNegSize{p1});
    BOOST_CHECK(ByRatioNegSize{p2} <= ByRatioNegSize{p1});
    BOOST_CHECK(ByRatioNegSize{p1} <= ByRatioNegSize{p4-p3});
    BOOST_CHECK(!(ByRatio{p3} < ByRatio{p1})); // not strictly worse
    BOOST_CHECK(ByRatio{p2} < ByRatio{p1}); // strictly lower feerate

    // "empty" comparisons
    BOOST_CHECK(!(ByRatio{p1} > ByRatio{empty})); // << will always result in false
    BOOST_CHECK(!(ByRatio{p1} < ByRatio{empty}));
    BOOST_CHECK(!(ByRatio{empty} > ByRatio{empty}));
    BOOST_CHECK(!(ByRatio{empty} < ByRatio{empty}));

    // empty is always bigger than everything else
    BOOST_CHECK(ByRatioNegSize{empty} > ByRatioNegSize{p1});
    BOOST_CHECK(ByRatioNegSize{empty} > ByRatioNegSize{p2});
    BOOST_CHECK(ByRatioNegSize{empty} > ByRatioNegSize{p3});
    BOOST_CHECK(ByRatioNegSize{empty} >= ByRatioNegSize{p1});
    BOOST_CHECK(ByRatioNegSize{empty} >= ByRatioNegSize{p2});
    BOOST_CHECK(ByRatioNegSize{empty} >= ByRatioNegSize{p3});

    // check "max" values for comparison
    FeeFrac oversized_1{4611686000000, 4000000};
    FeeFrac oversized_2{184467440000000, 100000};

    BOOST_CHECK(ByRatioNegSize{oversized_1} < ByRatioNegSize{oversized_2});
    BOOST_CHECK(ByRatioNegSize{oversized_1} <= ByRatioNegSize{oversized_2});
    BOOST_CHECK(ByRatio{oversized_1} < ByRatio{oversized_2});
    BOOST_CHECK(ByRatioNegSize{oversized_1} != ByRatioNegSize{oversized_2});

    BOOST_CHECK_EQUAL(oversized_1.EvaluateFeeDown(0), 0);
    BOOST_CHECK_EQUAL(oversized_1.EvaluateFeeDown(1), 1152921);
    BOOST_CHECK_EQUAL(oversized_1.EvaluateFeeDown(2), 2305843);
    BOOST_CHECK_EQUAL(oversized_1.EvaluateFeeDown(1548031267), 1784758530396540);
    BOOST_CHECK_EQUAL(oversized_1.EvaluateFeeUp(0), 0);
    BOOST_CHECK_EQUAL(oversized_1.EvaluateFeeUp(1), 1152922);
    BOOST_CHECK_EQUAL(oversized_1.EvaluateFeeUp(2), 2305843);
    BOOST_CHECK_EQUAL(oversized_1.EvaluateFeeUp(1548031267), 1784758530396541);

    // Test cases on the threshold where FeeFrac::Evaluate start using Mul/Div.
    BOOST_CHECK_EQUAL(FeeFrac(0x1ffffffff, 123456789).EvaluateFeeDown(98765432), 6871947728);
    BOOST_CHECK_EQUAL(FeeFrac(0x200000000, 123456789).EvaluateFeeDown(98765432), 6871947729);
    BOOST_CHECK_EQUAL(FeeFrac(0x200000001, 123456789).EvaluateFeeDown(98765432), 6871947730);
    BOOST_CHECK_EQUAL(FeeFrac(0x1ffffffff, 123456789).EvaluateFeeUp(98765432), 6871947729);
    BOOST_CHECK_EQUAL(FeeFrac(0x200000000, 123456789).EvaluateFeeUp(98765432), 6871947730);
    BOOST_CHECK_EQUAL(FeeFrac(0x200000001, 123456789).EvaluateFeeUp(98765432), 6871947731);

    // Tests paths that use double arithmetic
    FeeFrac busted{(static_cast<int64_t>(INT32_MAX)) + 1, INT32_MAX};
    BOOST_CHECK(!(ByRatioNegSize{busted} < ByRatioNegSize{busted}));

    FeeFrac max_fee{2100000000000000, INT32_MAX};
    BOOST_CHECK(!(ByRatioNegSize{max_fee} < ByRatioNegSize{max_fee}));
    BOOST_CHECK(!(ByRatioNegSize{max_fee} > ByRatioNegSize{max_fee}));
    BOOST_CHECK(ByRatioNegSize{max_fee} <= ByRatioNegSize{max_fee});
    BOOST_CHECK(ByRatioNegSize{max_fee} >= ByRatioNegSize{max_fee});

    BOOST_CHECK_EQUAL(max_fee.EvaluateFeeDown(0), 0);
    BOOST_CHECK_EQUAL(max_fee.EvaluateFeeDown(1), 977888);
    BOOST_CHECK_EQUAL(max_fee.EvaluateFeeDown(2), 1955777);
    BOOST_CHECK_EQUAL(max_fee.EvaluateFeeDown(3), 2933666);
    BOOST_CHECK_EQUAL(max_fee.EvaluateFeeDown(1256796054), 1229006664189047);
    BOOST_CHECK_EQUAL(max_fee.EvaluateFeeDown(INT32_MAX), 2100000000000000);
    BOOST_CHECK_EQUAL(max_fee.EvaluateFeeUp(0), 0);
    BOOST_CHECK_EQUAL(max_fee.EvaluateFeeUp(1), 977889);
    BOOST_CHECK_EQUAL(max_fee.EvaluateFeeUp(2), 1955778);
    BOOST_CHECK_EQUAL(max_fee.EvaluateFeeUp(3), 2933667);
    BOOST_CHECK_EQUAL(max_fee.EvaluateFeeUp(1256796054), 1229006664189048);
    BOOST_CHECK_EQUAL(max_fee.EvaluateFeeUp(INT32_MAX), 2100000000000000);

    FeeFrac max_fee2{1, 1};
    BOOST_CHECK(ByRatioNegSize{max_fee} >= ByRatioNegSize{max_fee2});

    // Test for integer overflow issue (https://github.com/bitcoin/bitcoin/issues/32294)
    BOOST_CHECK_EQUAL((FeeFrac{0x7ffffffdfffffffb, 0x7ffffffd}.EvaluateFeeDown(0x7fffffff)), 0x7fffffffffffffff);
}

BOOST_AUTO_TEST_SUITE_END()
