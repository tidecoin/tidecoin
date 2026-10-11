// Copyright (c) 2026 The Tidecoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <common/netif.h>
#include <netbase.h>
#include <test/util/setup_common.h>
#include <util/sock.h>

#include <boost/test/unit_test.hpp>

#include <cerrno>
#include <cstring>
#include <memory>
#include <utility>
#include <vector>

#if defined(__linux__)
#include <linux/rtnetlink.h>
#elif defined(__FreeBSD__)
#include <osreldate.h>
#if __FreeBSD_version >= 1400000
#define typeof __typeof
#include <netlink/netlink.h>
#include <netlink/netlink_route.h>
#endif
#endif

#if defined(__linux__) || (defined(__FreeBSD__) && __FreeBSD_version >= 1400000)
namespace {
class GatewayTestingSetup : public BasicTestingSetup
{
    const decltype(CreateSock) m_original{CreateSock};

public:
    ~GatewayTestingSetup() { CreateSock = m_original; }
};

class GatewaySock : public Sock
{
    const std::vector<unsigned char> m_data;
    const ssize_t m_received;
    mutable bool m_read{false};

public:
    using Sock::operator=;

    GatewaySock(std::vector<unsigned char> data, ssize_t received)
        : Sock{INVALID_SOCKET}, m_data{std::move(data)}, m_received{received} {}

    ssize_t Send(const void*, size_t len, int) const override { return len; }

    ssize_t Recv(void* buf, size_t len, int) const override
    {
        if (m_read || m_received < 0) {
            errno = EIO;
            return -1;
        }
        m_read = true;
        BOOST_REQUIRE(m_data.size() <= len);
        // Populate bytes beyond the reported receive length as well, to detect
        // a parser accepting stale buffer contents after an unaligned message.
        std::memset(buf, 0, len);
        std::memcpy(buf, m_data.data(), m_data.size());
        return m_received;
    }
};

std::vector<unsigned char> GatewayResponse()
{
    struct {
        nlmsghdr header;
        rtmsg route;
        rtattr attribute;
        unsigned char address[4];
    } message{};
    message.header.nlmsg_len = sizeof(message);
    message.header.nlmsg_type = RTM_NEWROUTE;
    message.route.rtm_family = AF_INET;
    message.attribute.rta_type = RTA_GATEWAY;
    message.attribute.rta_len = sizeof(rtattr) + sizeof(message.address);
    message.address[0] = 192;
    message.address[1] = 0;
    message.address[2] = 2;
    message.address[3] = 1;
    const auto* bytes = reinterpret_cast<const unsigned char*>(&message);
    return {bytes, bytes + sizeof(message)};
}
} // namespace

BOOST_FIXTURE_TEST_SUITE(netif_tests, GatewayTestingSetup)

BOOST_AUTO_TEST_CASE(gateway_receive_bounds)
{
    const auto gateway = GatewayResponse();
    const auto query = [&](const std::vector<unsigned char>& data, ssize_t received) {
        CreateSock = [data, received](int, int, int) {
            return std::make_unique<GatewaySock>(data, received);
        };
        return QueryDefaultGateway(NET_IPV4);
    };
    const auto result = query(gateway, gateway.size());
    BOOST_REQUIRE(result);
    BOOST_CHECK_EQUAL(result->ToStringAddr(), "192.0.2.1");
    BOOST_CHECK(!query(gateway, -1));
    BOOST_CHECK(!query(gateway, 0));
    BOOST_CHECK(!query(gateway, sizeof(nlmsghdr) - 1));
    BOOST_CHECK(!query(gateway, gateway.size() - 1));

    // A final message need not include alignment padding. NLMSG_NEXT may
    // subtract more bytes than remain; never treat that as a large unsigned size.
    for (unsigned int padding = 1; padding <= 3; ++padding) {
        nlmsghdr header{};
        header.nlmsg_type = NLMSG_NOOP;
        header.nlmsg_flags = NLM_F_MULTI;
        header.nlmsg_len = sizeof(header) + padding;
        std::vector<unsigned char> data(NLMSG_ALIGN(header.nlmsg_len));
        std::memcpy(data.data(), &header, sizeof(header));
        data.insert(data.end(), gateway.begin(), gateway.end());
        BOOST_CHECK(!query(data, header.nlmsg_len));
        const auto next_gateway = query(data, data.size());
        BOOST_REQUIRE(next_gateway);
        BOOST_CHECK_EQUAL(next_gateway->ToStringAddr(), "192.0.2.1");
    }

    // A complete netlink header does not imply a complete route header.
    // Leave valid route bytes beyond the declared length to ensure that the
    // parser checks message bounds, not just the received buffer size.
    for (unsigned int length = sizeof(nlmsghdr); length < NLMSG_LENGTH(sizeof(rtmsg)); ++length) {
        BOOST_TEST_CONTEXT("route message length " << length) {
            auto data = gateway;
            nlmsghdr header{};
            header.nlmsg_type = RTM_NEWROUTE;
            header.nlmsg_len = length;
            std::memcpy(data.data(), &header, sizeof(header));
            BOOST_CHECK(!query(data, length));
            BOOST_CHECK(!query(data, data.size()));
        }
    }

    // A route header with no attributes is valid. Continue to the next message
    // when it does not supply a gateway.
    auto data = gateway;
    data.resize(NLMSG_LENGTH(sizeof(rtmsg)));
    nlmsghdr header{};
    header.nlmsg_type = RTM_NEWROUTE;
    header.nlmsg_flags = NLM_F_MULTI;
    header.nlmsg_len = data.size();
    std::memcpy(data.data(), &header, sizeof(header));
    BOOST_CHECK(!query(data, data.size()));
    data.insert(data.end(), gateway.begin(), gateway.end());
    const auto next_gateway = query(data, data.size());
    BOOST_REQUIRE(next_gateway);
    BOOST_CHECK_EQUAL(next_gateway->ToStringAddr(), "192.0.2.1");
}

BOOST_AUTO_TEST_SUITE_END()
#endif
