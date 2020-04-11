# simple-beast-client
An easy to use HTTP client built on Boost.Beast

Super easy to use: 
1. Add the `include` directory to your project's include path.
2. Inlcude `httpclient.hpp`
3. Create the client instance shared pointer
4. Optionally set the fail action
5. Run the request

```c++
#include "httpclient.hpp"
...
// The client must attach to an existing ioContext
boost::asio::io_context ioContext;
// Create the client.
auto client = std::make_shared<simple_http::get_client>(
          ioContext, [](simple_http::empty_body_request &req,
                    simple_http::string_body_response &resp) {
      // Display the response to the console.
      std::cout << resp << '\n';
    });
// Optionally set a fail action
client->setFailHandler([](const simple_http::empty_body_request &req,
                        const simple_http::string_body_response &resp,
                        simple_http::fail_reason fr, 
                        boost::string_view message) {
    // Display the error message.
    std::cerr << message << '\n';
  });
// Run the asynchronous client request
client->get(simple_http::url(
          "http://user:passwd@httpbin.org/digest-auth/auth/user/passwd/MD5/never"));
```


Supports the following:

* HTTPS - through OpenSSL
* Basic Authentication
* Digest Authentication
* Timeouts
* Redirection
* Action on failure

Contains a URL class that can parse strings, based on Boost.Regex, accepting URLs similar to RFC3986, or can be constructed from components.

```c++
// Simple string format
simple_http::url google("http://google.com");
simple_http::url login("http://user:password@example.com/login");
// As components
simple_http::url anotherLogin("www.example.com", "/login", "https", "80", "user", "password");
```
More usage examples in main.cpp

When building, you must link the following:
* libcrypto - (Crypt32 on Windows) from OpenSSL for HTTPS and Digest Authentication
* libssl - (ssleay32 and libeay32 on Windows) from OpenSSL for HTTPS
* pthread - on Linux only
* Boost Regex
* Boost System - Alternately define "BOOST_ERROR_CODE_HEADER_ONLY"

See the example directory for a working CMake project (tested on Windows and Linux)
