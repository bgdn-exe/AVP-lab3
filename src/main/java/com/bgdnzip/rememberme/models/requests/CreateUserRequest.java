package com.bgdnzip.rememberme.models.requests;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

public record CreateUserRequest(String username, String password1, String password2) {
}
