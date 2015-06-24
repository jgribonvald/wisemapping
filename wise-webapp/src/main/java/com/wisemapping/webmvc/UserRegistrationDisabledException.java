package com.wisemapping.webmvc;

import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.http.HttpStatus;

@ResponseStatus(value = HttpStatus.NOT_FOUND)
public class UserRegistrationDisabledException extends RuntimeException {
    // def
}
