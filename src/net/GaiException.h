//
// Roman Sobkuliak 24.8.2017
//

#ifndef NET_GAIEXCEPTION_H
#define NET_GAIEXCEPTION_H

#include <exception>

class GaiException : public std::exception {
public:
    explicit GaiException(int code) : code_(code) {}

    const char *what() const noexcept override;
    const int code() const noexcept;
private:
    int code_;
};

#endif // NET_GAIEXCEPTION_H
