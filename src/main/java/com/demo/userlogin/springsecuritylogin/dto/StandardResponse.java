package com.demo.userlogin.springsecuritylogin.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class StandardResponse<T> {
    private T data;
    private String message;
    private boolean success;

    public StandardResponse(T data) {
        this.data = data;
        this.message = "Request was successful";
        this.success = true;
    }

    public StandardResponse(T data, String message) {
        this.data = data;
        this.message = message;
        this.success = true;
    }
}
