// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/args.h>
#include <i2p.h>
#include <logging.h>
#include <netaddress.h>
#include <netbase.h>
#include <test/util/logging.h>
#include <test/util/net.h>
#include <test/util/setup_common.h>
#include <util/readwritefile.h>
#include <util/strencodings.h>
#include <util/threadinterrupt.h>

#include <boost/test/unit_test.hpp>

#include <memory>
#include <string>

/// Save the log level and the value of CreateSock and restore them when the test ends.
class EnvTestingSetup : public BasicTestingSetup
{
public:
    explicit EnvTestingSetup(const ChainType chainType = ChainType::MAIN,
                             TestOpts opts = {})
        : BasicTestingSetup{chainType, opts},
          m_prev_log_level{LogInstance().LogLevel()},
          m_create_sock_orig{CreateSock}
    {
        LogInstance().SetLogLevel(BCLog::Level::Trace);
    }

    ~EnvTestingSetup()
    {
        CreateSock = m_create_sock_orig;
        LogInstance().SetLogLevel(m_prev_log_level);
    }

private:
    const BCLog::Level m_prev_log_level;
    const decltype(CreateSock) m_create_sock_orig;
};

BOOST_FIXTURE_TEST_SUITE(i2p_tests, EnvTestingSetup)

BOOST_AUTO_TEST_CASE(unlimited_recv)
{
    CreateSock = [](int, int, int) {
        return std::make_unique<StaticContentsSock>(std::string(i2p::sam::MAX_MSG_SIZE + 1, 'a'));
    };

    CThreadInterrupt interrupt;
    const std::optional<CService> addr{Lookup("127.0.0.1", 9000, false)};
    const Proxy sam_proxy(addr.value(), /*tor_stream_isolation=*/false);
    i2p::sam::Session session(gArgs.GetDataDirNet() / "test_i2p_private_key", sam_proxy, &interrupt);

    {
        ASSERT_DEBUG_LOG("Creating persistent SAM session");
        ASSERT_DEBUG_LOG("too many bytes without a terminator");

        i2p::Connection conn;
        bool proxy_error;
        BOOST_REQUIRE(!session.Connect(CService{}, conn, proxy_error));
    }
}

BOOST_AUTO_TEST_CASE(listen_ok_accept_fail)
{
    size_t num_sockets{0};
    CreateSock = [&num_sockets](int, int, int) {
        // clang-format off
        ++num_sockets;
        // First socket is the control socket for creating the session.
        if (num_sockets == 1) {
            return std::make_unique<StaticContentsSock>(
                // reply to HELLO
                "HELLO REPLY RESULT=OK VERSION=3.1\n"
                // reply to DEST GENERATE
                "DEST REPLY PUB=WnGOLXRBqHQhdVjFlWqRxJwz9hxx~2~wGc2Vplta1KhacY4tdEGodCF1WMWVapHEnDP2HHH~b~AZzZWmW1rUqFpxji10Qah0IXVYxZVqkcScM~Yccf9v8BnNlaZbWtSoWnGOLXRBqHQhdVjFlWqRxJwz9hxx~2~wGc2Vplta1KhacY4tdEGodCF1WMWVapHEnDP2HHH~b~AZzZWmW1rUqFpxji10Qah0IXVYxZVqkcScM~Yccf9v8BnNlaZbWtSoWnGOLXRBqHQhdVjFlWqRxJwz9hxx~2~wGc2Vplta1KhacY4tdEGodCF1WMWVapHEnDP2HHH~b~AZzZWmW1rUqFpxji10Qah0IXVYxZVqkcScM~Yccf9v8BnNlaZbWtSoWnGOLXRBqHQhdVjFlWqRxJwz9hxx~2~wGc2Vplta1KhacY4tdEGodCF1WMWVapHEnDP2HHH~b~AZzZWmW1rUqLE4SD-yjT48UNI7qiTUfIPiDitCoiTTz2cr4QGfw89rBQAEAAcAAA== PRIV=WnGOLXRBqHQhdVjFlWqRxJwz9hxx~2~wGc2Vplta1KhacY4tdEGodCF1WMWVapHEnDP2HHH~b~AZzZWmW1rUqFpxji10Qah0IXVYxZVqkcScM~Yccf9v8BnNlaZbWtSoWnGOLXRBqHQhdVjFlWqRxJwz9hxx~2~wGc2Vplta1KhacY4tdEGodCF1WMWVapHEnDP2HHH~b~AZzZWmW1rUqFpxji10Qah0IXVYxZVqkcScM~Yccf9v8BnNlaZbWtSoWnGOLXRBqHQhdVjFlWqRxJwz9hxx~2~wGc2Vplta1KhacY4tdEGodCF1WMWVapHEnDP2HHH~b~AZzZWmW1rUqFpxji10Qah0IXVYxZVqkcScM~Yccf9v8BnNlaZbWtSoWnGOLXRBqHQhdVjFlWqRxJwz9hxx~2~wGc2Vplta1KhacY4tdEGodCF1WMWVapHEnDP2HHH~b~AZzZWmW1rUqLE4SD-yjT48UNI7qiTUfIPiDitCoiTTz2cr4QGfw89rBQAEAAcAAOvuCIKTyv5f~1QgGq7XQl-IqBULTB5WzB3gw5yGPtd1p0AeoADrq1ccZggLPQ4ZLUsGK-HVw373rcTfvxrcuwenqVjiN4tbbYLWtP7xXGWj6fM6HyORhU63GphrjEePpMUHDHXd3o7pWGM-ieVVQSK~1MzF9P93pQWI3Do52EeNAayz4HbpPjNhVBzG1hUEFwznfPmUZBPuaOR4-uBm1NEWEuONlNOCctE4-U0Ukh94z-Qb55U5vXjR5G4apmBblr68t6Wm1TKlzpgFHzSqLryh3stWqrOKY1H0z9eZ2z1EkHFOpD5LyF6nf51e-lV7HLMl44TYzoEHK8RRVodtLcW9lacVdBpv~tOzlZERIiDziZODPETENZMz5oy9DQ7UUw==\n"
                // reply to SESSION CREATE
                "SESSION STATUS RESULT=OK\n"
                // dummy to avoid reporting EOF on the socket
                "a"
            );
        }
        // Subsequent sockets are for recreating the session or for listening and accepting incoming connections.
        if (num_sockets % 2 == 0) {
            // Replies to Listen() and Accept()
            return std::make_unique<StaticContentsSock>(
                // reply to HELLO
                "HELLO REPLY RESULT=OK VERSION=3.1\n"
                // reply to STREAM ACCEPT
                "STREAM STATUS RESULT=OK\n"
                // continued reply to STREAM ACCEPT, violating the protocol described at
                // https://geti2p.net/en/docs/api/samv3#Accept%20Response
                // should be base64, something like
                // "IchV608baDoXbqzQKSqFDmTXPVgoDbPAhZJvNRXXxi4hyFXrTxtoOhdurNApKoUOZNc9WCgNs8CFkm81FdfGLiHIVetPG2g6F26s0CkqhQ5k1z1YKA2zwIWSbzUV18YuIchV608baDoXbqzQKSqFDmTXPVgoDbPAhZJvNRXXxi4hyFXrTxtoOhdurNApKoUOZNc9WCgNs8CFkm81FdfGLiHIVetPG2g6F26s0CkqhQ5k1z1YKA2zwIWSbzUV18YuIchV608baDoXbqzQKSqFDmTXPVgoDbPAhZJvNRXXxi4hyFXrTxtoOhdurNApKoUOZNc9WCgNs8CFkm81FdfGLiHIVetPG2g6F26s0CkqhQ5k1z1YKA2zwIWSbzUV18YuIchV608baDoXbqzQKSqFDmTXPVgoDbPAhZJvNRXXxi4hyFXrTxtoOhdurNApKoUOZNc9WCgNs8CFkm81FdfGLlSreVaCuCS5sdb-8ToWULWP7kt~lRPDeUNxQMq3cRSBBQAEAAcAAA==\n"
                "STREAM STATUS RESULT=I2P_ERROR MESSAGE=\"Session was closed\"\n"
            );
        } else {
            // Another control socket, but without creating a destination (it is cached in the session).
            return std::make_unique<StaticContentsSock>(
                // reply to HELLO
                "HELLO REPLY RESULT=OK VERSION=3.1\n"
                // reply to SESSION CREATE
                "SESSION STATUS RESULT=OK\n"
                // dummy to avoid reporting EOF on the socket
                "a"
            );
        }
        // clang-format on
    };

    CThreadInterrupt interrupt;
    const CService addr{in6_addr(IN6ADDR_LOOPBACK_INIT), /*port=*/7656};
    const Proxy sam_proxy(addr, /*tor_stream_isolation=*/false);
    i2p::sam::Session session(gArgs.GetDataDirNet() / "test_i2p_private_key",
                              sam_proxy,
                              &interrupt);

    i2p::Connection conn;
    for (size_t i = 0; i < 5; ++i) {
        ASSERT_DEBUG_LOG("Creating persistent SAM session");
        ASSERT_DEBUG_LOG("Persistent SAM session" /* ... created */);
        ASSERT_DEBUG_LOG("Error accepting");
        ASSERT_DEBUG_LOG("Destroying SAM session");
        BOOST_REQUIRE(session.Listen(conn));
        BOOST_REQUIRE(!session.Accept(conn));
    }
}

BOOST_AUTO_TEST_CASE(damaged_private_key)
{
    CreateSock = [](int, int, int) {
        return std::make_unique<StaticContentsSock>("HELLO REPLY RESULT=OK VERSION=3.1\n"
                                                    "SESSION STATUS RESULT=OK DESTINATION=\n");
    };

    const auto i2p_private_key_file = m_args.GetDataDirNet() / "test_i2p_private_key_damaged";

    for (const auto& [file_contents, expected_error] : std::vector<std::tuple<std::string, std::string>>{
             {"", "The private key is too short (0 < 387)"},

             {"abcd", "The private key is too short (4 < 387)"},

             {std::string(386, '\0'), "The private key is too short (386 < 387)"},

             {std::string(385, '\0') + '\0' + '\1',
              "Certificate length (1) designates that the private key should be 388 bytes, but it is only "
              "387 bytes"},

             {std::string(385, '\0') + '\0' + '\5' + "abcd",
              "Certificate length (5) designates that the private key should be 392 bytes, but it is only "
              "391 bytes"}}) {
        BOOST_REQUIRE(WriteBinaryFile(i2p_private_key_file, file_contents));

        CThreadInterrupt interrupt;
        const CService addr{in6_addr(IN6ADDR_LOOPBACK_INIT), /*port=*/7656};
        const Proxy sam_proxy{addr, /*tor_stream_isolation=*/false};
        i2p::sam::Session session(i2p_private_key_file, sam_proxy, &interrupt);

        {
            ASSERT_DEBUG_LOG("Creating persistent SAM session");
            ASSERT_DEBUG_LOG(expected_error);

            i2p::Connection conn;
            bool proxy_error;
            BOOST_CHECK(!session.Connect(CService{}, conn, proxy_error));
        }
    }
}

BOOST_AUTO_TEST_CASE(persistent_key_failures)
{
    class RecordingSock : public StaticContentsSock
    {
        std::string& m_sent;
        RecordingSock& operator=(Sock&&) override { std::terminate(); }
    public:
        RecordingSock(const std::string& reply, std::string& sent) : StaticContentsSock(reply), m_sent{sent} {}
        ssize_t Send(const void* data, size_t len, int) const override
        {
            m_sent.append(static_cast<const char*>(data), len);
            return len;
        }
    };
    const auto path = m_args.GetDataDirNet() / "persistent-key";
    CThreadInterrupt interrupt;
    const CService addr{in6_addr(IN6ADDR_LOOPBACK_INIT), /*port=*/7656};
    const Proxy sam_proxy{addr, /*tor_stream_isolation=*/false};
    std::string sent;
    // Structurally valid destination and private material; the SAM mock does not
    // perform cryptographic validation. Keep the certificate length zero.
    const std::string key(663, '\0');
    std::string replies;
    size_t sockets{0};
    CreateSock = [&](int, int, int) {
        return std::make_unique<RecordingSock>("HELLO REPLY RESULT=OK VERSION=3.1\n" +
            (++sockets == 1 ? replies : "STREAM STATUS RESULT=OK\n"), sent);
    };
    const auto listen = [&] {
        sockets = 0;
        i2p::sam::Session session(path, sam_proxy, &interrupt);
        i2p::Connection conn;
        return session.Listen(conn);
    };
    // Read errors must not send DEST GENERATE, SESSION CREATE, or alter the file.
    for (const std::string& data : {std::string{}, std::string(386, '\0'), std::string(i2p::sam::MAX_PRIVATE_KEY_SIZE + 1, 'x')}) {
        BOOST_REQUIRE(WriteBinaryFile(path, data));
        sent.clear();
        BOOST_CHECK(!listen());
        BOOST_CHECK_EQUAL(sent, "HELLO VERSION MIN=3.1 MAX=3.1\n");
        BOOST_CHECK_EQUAL(ReadBinaryFile(path).second, data);
    }
    fs::remove(path);
    fs::create_directory(path);
    sent.clear();
    BOOST_CHECK(!listen());
    BOOST_CHECK_EQUAL(sent, "HELLO VERSION MIN=3.1 MAX=3.1\n");
    BOOST_CHECK(fs::is_directory(path));
    fs::remove(path);

    replies = "DEST REPLY PRIV=AAAA\n";
    sent.clear();
    BOOST_CHECK(!listen());
    BOOST_CHECK(!fs::exists(path));
    BOOST_CHECK(sent.find("SESSION CREATE ") == std::string::npos);

    // Failure to persist a newly generated key must precede SESSION CREATE.
    replies = "DEST REPLY PRIV=" + EncodeBase64(key) + "\n";
    fs::create_directory(path + ".tmp");
    sent.clear();
    BOOST_CHECK(!listen());
    BOOST_CHECK(sent.find("DEST GENERATE ") != std::string::npos);
    BOOST_CHECK(sent.find("SESSION CREATE ") == std::string::npos);
    BOOST_CHECK(!fs::exists(path));
    fs::remove(path + ".tmp");

    replies += "SESSION STATUS RESULT=OK\nSTREAM STATUS RESULT=OK\n";
    sent.clear();
    BOOST_CHECK(listen());
    BOOST_CHECK_EQUAL(ReadBinaryFile(path).second, key);
    BOOST_CHECK(sent.find("SESSION CREATE ") != std::string::npos);

    // Reopening uses the same stored key without generating or writing another.
    // A blocked temporary path would make any unnecessary rewrite fail.
    fs::create_directory(path + ".tmp");
    replies = "SESSION STATUS RESULT=OK\nSTREAM STATUS RESULT=OK\n";
    sent.clear();
    BOOST_CHECK(listen());
    BOOST_CHECK(sent.find("DEST GENERATE ") == std::string::npos);
    BOOST_CHECK(sent.find("DESTINATION=" + EncodeBase64(key)) != std::string::npos);
    BOOST_CHECK_EQUAL(ReadBinaryFile(path).second, key);
    fs::remove(path + ".tmp");

    // The local bound accepts the entire buffer at the limit. Leave algorithm
    // validation to the SAM router rather than imposing a guessed 4 KiB limit.
    const std::string large_key(i2p::sam::MAX_PRIVATE_KEY_SIZE, '\0');
    BOOST_REQUIRE(WriteBinaryFile(path, large_key));
    sent.clear();
    BOOST_CHECK(listen());
    BOOST_CHECK(sent.find("DEST GENERATE ") == std::string::npos);
    BOOST_CHECK(sent.find("DESTINATION=" + EncodeBase64(large_key)) != std::string::npos);
#ifndef WIN32
    // A mounted/read-only key can be reached through a link. Using an existing
    // key must require neither rewriting it nor opening its directory for sync.
    const auto key_directory = m_args.GetDataDirNet() / "mounted-i2p-key";
    fs::create_directory(key_directory);
    const auto target = key_directory / "key";
    BOOST_REQUIRE(WriteBinaryFile(target, key));
    fs::remove(path);
    fs::create_symlink(target, path);
    fs::permissions(target, fs::perms::owner_read);
    fs::permissions(key_directory, fs::perms::owner_exec);
    sent.clear();
    const bool loaded_linked_key = listen();
    fs::permissions(key_directory, fs::perms::owner_all);
    BOOST_CHECK(loaded_linked_key);
    BOOST_CHECK(sent.find("DEST GENERATE ") == std::string::npos);
    BOOST_CHECK(sent.find("DESTINATION=" + EncodeBase64(key)) != std::string::npos);
    BOOST_CHECK(fs::is_symlink(path));
    BOOST_CHECK_EQUAL(ReadBinaryFile(target).second, key);
    fs::remove(target);
    sent.clear();
    BOOST_CHECK(!listen());
    BOOST_CHECK_EQUAL(sent, "HELLO VERSION MIN=3.1 MAX=3.1\n");
    BOOST_CHECK(fs::is_symlink(path));
    BOOST_CHECK(!fs::exists(target));
#endif
}

BOOST_AUTO_TEST_SUITE_END()
