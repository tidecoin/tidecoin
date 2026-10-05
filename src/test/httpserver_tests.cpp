// Copyright (c) 2012-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <httpserver.h>
#include <common/args.h>
#include <rpc/protocol.h>
#include <support/events.h>
#include <util/signalinterrupt.h>

#include <event2/buffer.h>
#include <event2/http.h>

#include <stdexcept>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(httpserver_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(test_query_parameters)
{
    std::string uri {};

    // No parameters
    uri = "localhost:8080/rest/headers/someresource.json";
    BOOST_CHECK(!GetQueryParameterFromUri(uri.c_str(), "p1").has_value());

    // Single parameter
    uri = "localhost:8080/rest/endpoint/someresource.json?p1=v1";
    BOOST_CHECK_EQUAL(GetQueryParameterFromUri(uri.c_str(), "p1").value(), "v1");
    BOOST_CHECK(!GetQueryParameterFromUri(uri.c_str(), "p2").has_value());

    // Multiple parameters
    uri = "/rest/endpoint/someresource.json?p1=v1&p2=v2";
    BOOST_CHECK_EQUAL(GetQueryParameterFromUri(uri.c_str(), "p1").value(), "v1");
    BOOST_CHECK_EQUAL(GetQueryParameterFromUri(uri.c_str(), "p2").value(), "v2");

    // If the query string contains duplicate keys, the first value is returned
    uri = "/rest/endpoint/someresource.json?p1=v1&p1=v2";
    BOOST_CHECK_EQUAL(GetQueryParameterFromUri(uri.c_str(), "p1").value(), "v1");

    // Invalid query string syntax is the same as not having parameters
    uri = "/rest/endpoint/someresource.json&p1=v1&p2=v2";
    BOOST_CHECK(!GetQueryParameterFromUri(uri.c_str(), "p1").has_value());

    // URI with invalid characters (%) raises a runtime error regardless of which query parameter is queried
    uri = "/rest/endpoint/someresource.json&p1=v1&p2=v2%";
    BOOST_CHECK_EXCEPTION(GetQueryParameterFromUri(uri.c_str(), "p1"), std::runtime_error, HasReason("URI parsing failed, it likely contained RFC 3986 invalid characters"));
}

BOOST_AUTO_TEST_CASE(handler_exceptions_preserve_server)
{
    // A real server with one worker proves subsequent requests are handled by
    // the same worker after an exception. Bind only to loopback.
    gArgs.ForceSetArg("-rpcallowip", "127.0.0.1");
    gArgs.ForceSetArg("-rpcthreads", "1");
    util::SignalInterrupt interrupt;
    uint16_t port{0};
    bool initialized{false};
    for (int attempt{0}; attempt < 16 && !initialized; ++attempt) {
        port = 30000 + m_rng.randrange(20000);
        gArgs.ForceSetArg("-rpcbind", "127.0.0.1:" + std::to_string(port));
        initialized = InitHTTPServer(interrupt);
    }
    BOOST_REQUIRE(initialized);
    struct ServerCleanup {
        ~ServerCleanup()
        {
            InterruptHTTPServer();
            StopHTTPServer();
            UnregisterHTTPHandler("/exception-test/", false);
        }
    } cleanup;
    RegisterHTTPHandler("/exception-test/", false, [](HTTPRequest* request, const std::string& path) {
        if (path == "standard") throw std::runtime_error("synthetic-secret-exception");
        if (path == "unknown") throw 7;
        request->WriteReply(HTTP_OK, "ok");
        if (path == "after-reply") throw std::runtime_error("synthetic-secret-after-reply");
        return true;
    });
    StartHTTPServer();

    struct Response {
        event_base* base;
        int status{0};
        std::string body;
        std::string connection;
    };
    auto get = [&](const std::string& path) {
        auto base = obtain_event_base();
        auto connection = obtain_evhttp_connection_base(base.get(), "127.0.0.1", port);
        evhttp_connection_set_timeout(connection.get(), 5);
        Response response{base.get(), 0, {}, {}};
        auto* request = evhttp_request_new([](evhttp_request* reply, void* arg) {
            auto& result = *static_cast<Response*>(arg);
            if (reply) {
                result.status = evhttp_request_get_response_code(reply);
                auto* buffer = evhttp_request_get_input_buffer(reply);
                const auto size = evbuffer_get_length(buffer);
                if (size) result.body.assign(reinterpret_cast<const char*>(evbuffer_pullup(buffer, size)), size);
                if (const char* header = evhttp_find_header(evhttp_request_get_input_headers(reply), "Connection")) {
                    result.connection = header;
                }
            }
            event_base_loopbreak(result.base);
        }, &response);
        BOOST_REQUIRE(request);
        evhttp_add_header(evhttp_request_get_output_headers(request), "Host", "localhost");
        BOOST_REQUIRE_EQUAL(evhttp_make_request(connection.get(), request, EVHTTP_REQ_GET, ("/exception-test/" + path).c_str()), 0);
        event_base_dispatch(base.get());
        return response;
    };
    for (int round{0}; round < 3; ++round) {
        for (const std::string path : {"standard", "unknown", "after-reply"}) {
            const auto response = get(path);
            if (path == "after-reply") {
                BOOST_CHECK_EQUAL(response.status, HTTP_OK);
                BOOST_CHECK_EQUAL(response.body, "ok");
            } else {
                BOOST_CHECK_EQUAL(response.status, HTTP_INTERNAL_SERVER_ERROR);
                BOOST_CHECK_EQUAL(response.body, "Internal server error");
                BOOST_CHECK_EQUAL(response.connection, "close");
            }
            const auto healthy = get("ok");
            BOOST_CHECK_EQUAL(healthy.status, HTTP_OK);
            BOOST_CHECK_EQUAL(healthy.body, "ok");
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
