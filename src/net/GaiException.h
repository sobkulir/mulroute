//
// Roman Sobkuliak 24.8.2017
//

#ifndef NET_GAIEXCEPTION_H
#define NET_GAIEXCEPTION_H

#include <exception>

class GaiException : public std::exception {
public:
    explicit GaiException(int code) : _code(code) {}

    const char *what() const noexcept override;
    const int code() const noexcept;
private:
    int _code;
};

#endif // NET_GAIEXCEPTION_H