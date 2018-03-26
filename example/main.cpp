/*
* simple-beast-client example
*/

#include "httpclient.hpp"
#include <boost/asio.hpp>
#include <iostream>

int main(int argc, char *argv[]) {
  std::cout << "Start up\n";

  try {
    boost::asio::io_context ioContext;

    // URL parsing validation tests - will throw exception if any URL is invalid.
    simple_http::url test("http://test.com/target");
    simple_http::url test2("www.test.com/target2");
    simple_http::url test3("https://test.com");
    simple_http::url test4("test.com:80");
    simple_http::url test5("http://33.com:400/target");
    simple_http::url test6("http://user:pass@33.com:400/target?val=1&val2=2");
    simple_http::url test7("http://user:pass@33.com");
    
    
    // Run an asynchronous client test - connect with Digest Authentication
    {
      auto client = std::make_shared<simple_http::get_client>(
          ioContext, [](simple_http::empty_body_request &req,
                        simple_http::string_body_response &resp) {
            // Display the response to the console.
            std::cout << resp << '\n';
          });
      // Run the GET request to httpbin.org
      client->get(simple_http::url(
          "http://user:passwd@httpbin.org/digest-auth/auth/user/passwd/MD5/never"));
    }

    // Run another asynchronous client test - redirection and HTTPS connect.
    // This example shows the boost::beast request and response template classes.
    {
      auto client = std::make_shared<simple_http::get_client>(
          ioContext, [](boost::beast::http::request<boost::beast::http::empty_body> &req,
                        boost::beast::http::response<boost::beast::http::string_body> &resp) {
            std::cout << resp << '\n';
          });
      client->setFailHandler([](simple_http::empty_body_request &req,
                            simple_http::string_body_response &resp, simple_http::fail_reason fr, boost::string_view message) {
        std::cout << message << '\n';
      });
      // Connect to www.dpwlabs.com - which enforces HTTPS, through a 301 response.
      // The 1 argument is the number of redirects to follow.
      client->get(simple_http::url("http://google.com"), 1);
    }

    // Run the until requests are complete.
    ioContext.run();
  } catch (std::exception &e) {
    std::cerr << "exception: " << e.what() << "\n";
  }
  return 0;
}
